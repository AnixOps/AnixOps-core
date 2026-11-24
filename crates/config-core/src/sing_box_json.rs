//! sing-box JSON subscriptions.

use super::*;

pub(crate) fn parse_sing_box_json_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_json::from_str::<RawSingBoxDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(outbounds) = raw.outbounds else {
        return Ok(None);
    };
    if outbounds.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box json outbounds cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("sing-box outbound");
    // Whether any entry reads as an outbound; when none does, the text is
    // not a sing-box document and the next format gets it.
    let mut readable = false;
    for (index, value) in outbounds.into_iter().enumerate() {
        let tag = value
            .get("tag")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if kind
            .as_deref()
            .is_some_and(|kind| is_ignored_sing_box_outbound(&normalized_token(kind)))
        {
            readable = true;
            continue;
        }
        let outbound = match serde_json::from_value::<RawSingBoxOutbound>(value) {
            Ok(outbound) => outbound,
            Err(_) => {
                skipped.skip(
                    index,
                    tag.as_deref(),
                    kind.as_deref(),
                    domain_error(
                        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                        "sing-box outbound fields have unexpected types",
                    ),
                );
                continue;
            }
        };
        readable = true;
        match parse_sing_box_outbound(outbound, source_id) {
            Ok(Some(node)) => nodes.push(node),
            Ok(None) => {}
            Err(error) => skipped.skip(index, tag.as_deref(), kind.as_deref(), error),
        }
    }
    if !readable {
        return Ok(None);
    }
    node_id::assign_subscription_node_ids(&mut nodes);
    resolve_vias(&mut nodes);

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box json outbounds must contain at least one supported proxy outbound",
            )
        })
        .map(Some)
}

/// Turns each node's `detour` tag into the id of the imported node with that
/// name. A tag that names no imported node stays unresolved, and the node
/// cannot run (the importer reports it), rather than leaving beside its chain.
pub(crate) fn resolve_vias(nodes: &mut [NodeDescriptor]) {
    let mut ids = BTreeMap::new();
    for node in nodes.iter() {
        ids.entry(node.name.clone())
            .or_insert_with(|| node.id.clone());
    }
    for node in nodes.iter_mut() {
        let Some(index) = node
            .metadata
            .iter()
            .position(|entry| entry.key == NODE_METADATA_VIA_UNRESOLVED)
        else {
            continue;
        };
        if let Some(id) = ids.get(&node.metadata[index].value) {
            node.metadata[index] = MetadataEntry {
                key: NODE_METADATA_VIA.to_string(),
                value: id.clone(),
            };
        }
    }
}

pub(crate) fn parse_sing_box_outbound(
    raw: RawSingBoxOutbound,
    source_id: &str,
) -> DomainResult<Option<NodeDescriptor>> {
    let RawSingBoxOutbound {
        protocol,
        tag,
        server,
        server_port,
        server_ports,
        method,
        password,
        uuid,
        flow,
        security,
        alter_id,
        congestion_control,
        obfs,
        tls,
        transport,
        detour,
        multiplex,
        username,
        mtu,
        encrypt,
        plugin,
        version,
        path: http_path,
        headers: http_headers,
    } = raw;
    let protocol =
        required_sing_box_scalar_field(protocol, "sing-box outbound type cannot be empty")?;
    let protocol_token = normalized_token(&protocol);
    if is_ignored_sing_box_outbound(&protocol_token) {
        return Ok(None);
    }

    let host = required_sing_box_scalar_field(server, "sing-box outbound server cannot be empty")?;
    let (port, server_ports) = parse_sing_box_outbound_port(
        server_port,
        server_ports.map(RawSingBoxStringList::into_values),
        matches!(protocol_token.as_str(), "hysteria2" | "hy2"),
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_sing_box_scalar_field(
                method,
                "sing-box shadowsocks method cannot be empty",
            )?;
            let password = required_sing_box_scalar_field(
                password,
                "sing-box shadowsocks password cannot be empty",
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
            metadata.extend(shadowsocks_plugin_entry(optional_sing_box_scalar_field(
                plugin,
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box trojan password cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                value: password,
            }];
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Trojan, "trojan", metadata)
        }
        "vless" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = optional_sing_box_scalar_field(flow) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(security) = optional_sing_box_scalar_field(security) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_SECURITY.to_string(),
                    value: security,
                });
            }
            if let Some(alter_id) = optional_sing_box_scalar_field(alter_id) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Vmess, "vmess", metadata)
        }
        "hysteria2" | "hy2" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box hysteria2 password cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
                value: password,
            }];
            if let Some(server_ports) = server_ports {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
                    value: server_ports,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            append_sing_box_hysteria2_obfs_metadata(&mut metadata, obfs)?;
            (Protocol::Hysteria2, "hysteria2", metadata)
        }
        "tuic" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box tuic uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_TUIC_UUID.to_string(),
                value: uuid,
            }];
            if let Some(password) = optional_sing_box_scalar_field(password) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_PASSWORD.to_string(),
                    value: password,
                });
            }
            if let Some(congestion_control) = optional_sing_box_scalar_field(congestion_control) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
                    value: congestion_control,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            (Protocol::Tuic, "tuic", metadata)
        }
        "iwan" => {
            let username =
                required_sing_box_scalar_field(username, "sing-box iwan username cannot be empty")?;
            let password =
                required_sing_box_scalar_field(password, "sing-box iwan password cannot be empty")?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_IWAN_USERNAME.to_string(),
                    value: username,
                },
                MetadataEntry {
                    key: NODE_METADATA_IWAN_PASSWORD.to_string(),
                    value: password,
                },
            ];
            if let Some(mtu) = optional_sing_box_scalar_field(mtu) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_IWAN_MTU.to_string(),
                    value: mtu,
                });
            }
            if let Some(encrypt) = encrypt {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_IWAN_ENCRYPT.to_string(),
                    value: encrypt.to_string(),
                });
            }
            (Protocol::Iwan, "iwan", metadata)
        }
        "http" => {
            let path = clash_option_text(http_path.as_ref()).is_some_and(|path| path != "/");
            let headers = http_headers
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .is_some_and(|headers| !headers.is_empty());
            let mut metadata = plain_proxy_metadata(
                PlainProxyFields {
                    username: optional_sing_box_scalar_field(username),
                    password: optional_sing_box_scalar_field(password),
                    unsupported: (path || headers)
                        .then_some(NODE_UNSUPPORTED_OPTION_HTTP_PROXY_HEADERS),
                    ..PlainProxyFields::default()
                },
                &host,
            );
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            (Protocol::Http, "http", metadata)
        }
        "socks" => {
            if let Some(version) = clash_option_text(version.as_ref()) {
                if version != "5" {
                    return Err(domain_error(
                        SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                        "sing-box socks outbound version must be 5 for catalog import",
                    ));
                }
            }
            let metadata = plain_proxy_metadata(
                PlainProxyFields {
                    username: optional_sing_box_scalar_field(username),
                    password: optional_sing_box_scalar_field(password),
                    ..PlainProxyFields::default()
                },
                &host,
            );
            (Protocol::Socks, "socks", metadata)
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box outbound type must be shadowsocks, trojan, vless, vmess, hysteria2, tuic, iwan, http, or socks for catalog import",
            ));
        }
    };
    if let Some(detour) = optional_sing_box_scalar_field(detour) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VIA_UNRESOLVED.to_string(),
            value: detour,
        });
    }
    metadata.extend(multiplex_metadata(multiplex.as_ref()));

    let tag = optional_sing_box_scalar_field(tag);
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let fallback_id = format!("{host_id}-{port}");
    let name = tag
        .clone()
        .unwrap_or_else(|| format!("sing-box-{protocol_tag}-{fallback_id}"));
    let name_id = tag.as_deref().unwrap_or(&fallback_id);
    let name_id = sanitize_identifier(name_id);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("sing-box-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "sing-box-json".to_string(),
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
            "sing-box-json".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

pub(crate) fn parse_sing_box_outbound_port(
    server_port: Option<RawSingBoxScalar>,
    server_ports: Option<Vec<String>>,
    supports_port_ranges: bool,
) -> DomainResult<(u16, Option<String>)> {
    if supports_port_ranges {
        if let Some(server_ports) = server_ports {
            let normalized = normalize_hysteria2_server_port_ranges(
                server_ports,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            let first_port = normalized.first().ok_or_else(|| {
                domain_error(
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                    "sing-box hysteria2 server_ports cannot be empty",
                )
            })?;
            let first_port = hysteria2_server_port_range_start(
                first_port,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            return Ok((first_port, Some(normalized.join(","))));
        }
    }

    let port = required_sing_box_scalar_field(
        server_port,
        "sing-box outbound server_port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box outbound server_port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        "sing-box outbound server_port must be between 1 and 65535",
    )?;

    Ok((port, None))
}

pub(crate) fn sing_box_v2ray_tls_metadata(
    raw: Option<RawSingBoxTls>,
    host: &str,
    default_enabled: bool,
) -> DomainResult<Metadata> {
    let Some(raw) = raw else {
        return Ok(vec![MetadataEntry {
            key: NODE_METADATA_TLS_ENABLED.to_string(),
            value: default_enabled.to_string(),
        }]);
    };
    let RawSingBoxTls {
        enabled,
        server_name,
        insecure,
        alpn,
        certificate_sha256,
        certificate_public_key_sha256,
        utls,
        reality,
    } = raw;
    let reality_enabled = reality
        .as_ref()
        .and_then(|reality| reality.enabled)
        .unwrap_or(false);
    let enabled = enabled.unwrap_or(default_enabled) || reality_enabled;
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_TLS_ENABLED.to_string(),
            value: enabled.to_string(),
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: optional_sing_box_scalar_field(server_name).unwrap_or_else(|| host.to_string()),
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: insecure.unwrap_or(false).to_string(),
        },
    ];
    if let Some(alpn) = normalize_non_empty_metadata_values(
        alpn.map(RawSingBoxStringList::into_values),
        "sing-box tls alpn values cannot be empty",
    )? {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    metadata.extend(sing_box_pin_metadata(
        certificate_sha256,
        certificate_public_key_sha256,
    )?);
    if let Some(utls) = utls.filter(|utls| utls.enabled.unwrap_or(false)) {
        let fingerprint = required_sing_box_scalar_field(
            utls.fingerprint,
            "sing-box tls utls fingerprint cannot be empty when utls is enabled",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_UTLS_FINGERPRINT.to_string(),
            value: fingerprint,
        });
    }
    if let Some(reality) = reality.filter(|reality| reality.enabled.unwrap_or(false)) {
        let public_key = required_sing_box_scalar_field(
            reality.public_key,
            "sing-box tls reality public_key cannot be empty when reality is enabled",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_REALITY_PUBLIC_KEY.to_string(),
            value: public_key,
        });
        if let Some(short_id) = optional_sing_box_scalar_field(reality.short_id) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_REALITY_SHORT_ID.to_string(),
                value: short_id,
            });
        }
    }
    Ok(metadata)
}

pub(crate) fn append_sing_box_v2ray_transport_metadata(
    metadata: &mut Metadata,
    raw: Option<RawSingBoxTransport>,
) -> DomainResult<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let RawSingBoxTransport {
        kind,
        host,
        path,
        service_name,
        headers,
    } = raw;
    let kind = required_sing_box_scalar_field(kind, "sing-box transport type cannot be empty")?;
    let kind = match normalized_token(&kind).as_str() {
        "ws" | "websocket" => "ws",
        "grpc" => "grpc",
        "http" | "h2" => "http",
        "httpupgrade" | "http_upgrade" => "httpupgrade",
        "quic" => "quic",
        "tcp" | "raw" | "none" => return Ok(()),
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box outbound transport must be ws, grpc, http, httpupgrade, or quic for catalog import",
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_V2RAY_TRANSPORT_TYPE.to_string(),
        value: kind.to_string(),
    });
    let host = host.or_else(|| headers.and_then(|headers| headers.host));
    if let Some(host) = normalize_non_empty_metadata_values(
        host.map(RawSingBoxStringList::into_values),
        "sing-box transport host values cannot be empty",
    )? {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_HOST.to_string(),
            value: host.join(","),
        });
    }
    if let Some(path) = optional_sing_box_scalar_field(path) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_PATH.to_string(),
            value: path,
        });
    }
    if let Some(service_name) = optional_sing_box_scalar_field(service_name) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME.to_string(),
            value: service_name,
        });
    }
    Ok(())
}

pub(crate) fn sing_box_tls_metadata(
    raw: Option<RawSingBoxTls>,
    host: &str,
) -> DomainResult<Metadata> {
    let (server_name, insecure, alpn, certificate_sha256, certificate_public_key_sha256) = match raw
    {
        Some(raw) => (
            optional_sing_box_scalar_field(raw.server_name).unwrap_or_else(|| host.to_string()),
            raw.insecure.unwrap_or(false),
            raw.alpn.map(RawSingBoxStringList::into_values),
            raw.certificate_sha256,
            raw.certificate_public_key_sha256,
        ),
        None => (host.to_string(), false, None, None, None),
    };
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: server_name,
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: insecure.to_string(),
        },
    ];
    if let Some(alpn) =
        normalize_non_empty_metadata_values(alpn, "sing-box tls alpn values cannot be empty")?
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    metadata.extend(sing_box_pin_metadata(
        certificate_sha256,
        certificate_public_key_sha256,
    )?);
    Ok(metadata)
}

/// The pin entries of a sing-box `tls` object (both lists base64; see
/// [`certificate_pin_metadata`]).
pub(crate) fn sing_box_pin_metadata(
    certificate_sha256: Option<RawSingBoxStringList>,
    certificate_public_key_sha256: Option<RawSingBoxStringList>,
) -> DomainResult<Metadata> {
    let certificate = normalize_non_empty_metadata_values(
        certificate_sha256.map(RawSingBoxStringList::into_values),
        "sing-box tls certificate_sha256 values cannot be empty",
    )?
    .unwrap_or_default();
    let public_key = normalize_non_empty_metadata_values(
        certificate_public_key_sha256.map(RawSingBoxStringList::into_values),
        "sing-box tls certificate_public_key_sha256 values cannot be empty",
    )?
    .unwrap_or_default();
    Ok(certificate_pin_metadata(&certificate, &public_key))
}

pub(crate) fn append_sing_box_hysteria2_obfs_metadata(
    metadata: &mut Metadata,
    obfs: Option<RawSingBoxHysteria2Obfs>,
) -> DomainResult<()> {
    let Some(obfs) = obfs else {
        return Ok(());
    };
    let kind =
        required_sing_box_scalar_field(obfs.kind, "sing-box hysteria2 obfs type cannot be empty")?;
    let kind = normalized_token(&kind);
    if !matches!(kind.as_str(), "salamander" | "gecko") {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box hysteria2 obfs type must be salamander or gecko",
        ));
    }
    let password = required_sing_box_scalar_field(
        obfs.password,
        "sing-box hysteria2 obfs password cannot be empty",
    )?;
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
        value: kind.clone(),
    });
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
        value: password,
    });
    if kind == "gecko" {
        if let Some(value) = obfs.min_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
        if let Some(value) = obfs.max_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
    }
    Ok(())
}

pub(crate) fn normalize_non_empty_metadata_values(
    values: Option<Vec<String>>,
    message: &'static str,
) -> DomainResult<Option<Vec<String>>> {
    values
        .map(|values| {
            values
                .into_iter()
                .map(|value| {
                    required_trimmed(value, SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE, message)
                })
                .collect::<DomainResult<Vec<_>>>()
        })
        .transpose()
}

pub(crate) fn is_ignored_sing_box_outbound(protocol_token: &str) -> bool {
    matches!(
        protocol_token,
        "direct" | "block" | "dns" | "selector" | "urltest" | "bridge"
    )
}

pub(crate) fn required_sing_box_scalar_field(
    raw: Option<RawSingBoxScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            message,
        ));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        message,
    )
}

pub(crate) fn optional_sing_box_scalar_field(raw: Option<RawSingBoxScalar>) -> Option<String> {
    let text = raw?.into_text().trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}
