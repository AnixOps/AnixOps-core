//! Share-link subscriptions: one link per line, per protocol, and their
//! query parameters.

use super::*;

pub(crate) fn parse_proxy_link_lines(
    source_id: &str,
    content: &str,
) -> DomainResult<SubscriptionDocument> {
    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("share link");
    // An AnixOps `#anixops:path=<kind>` line describes the link after it.
    let mut path: Option<String> = None;

    for (index, line) in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if let Some(comment) = line.strip_prefix('#') {
            if let Some(kind) = comment.trim().strip_prefix(ANIXOPS_PATH_MARK) {
                path = Some(kind.trim().to_string()).filter(|kind| is_path_kind(kind));
            }
            continue;
        }
        let path = path.take();
        let Some(parser) = share_link_parser(line) else {
            continue;
        };
        let scheme = line.split_once("://").map(|(scheme, _)| scheme);
        let parsed =
            take_link_via(line).and_then(|(link, via)| parser(&link).map(|node| (node, via)));
        let (mut node, via) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                skipped.skip(index, None, scheme, error);
                continue;
            }
        };
        if let Some(via) = via {
            node.metadata.push(MetadataEntry {
                key: NODE_METADATA_VIA_UNRESOLVED.to_string(),
                value: via,
            });
        }
        if let Some(path) = path {
            node.metadata.push(MetadataEntry {
                key: NODE_METADATA_PATH.to_string(),
                value: path,
            });
        }
        node.metadata.push(MetadataEntry {
            key: "subscription.source_id".to_string(),
            value: source_id.to_string(),
        });
        nodes.push(node);
    }
    node_id::assign_subscription_node_ids(&mut nodes);
    resolve_vias(&mut nodes);

    skipped.finish(nodes, || {
        domain_error(
            SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
            "subscription link list did not contain supported proxy links",
        )
    })
}

/// The parser for a share link's scheme; `None` for lines of other schemes,
/// which a link list skips silently.
pub(crate) fn share_link_parser(line: &str) -> Option<fn(&str) -> DomainResult<NodeDescriptor>> {
    let parser: fn(&str) -> DomainResult<NodeDescriptor> = if line.starts_with("ss://") {
        parse_shadowsocks_link
    } else if line.starts_with("trojan://") {
        parse_trojan_link
    } else if line.starts_with("vless://") {
        parse_vless_link
    } else if line.starts_with("vmess://") {
        parse_vmess_link
    } else if line.starts_with("hysteria2://") || line.starts_with("hy2://") {
        parse_hysteria2_link
    } else if line.starts_with("tuic://") {
        parse_tuic_link
    } else if line.starts_with("wireguard://") {
        parse_wireguard_link
    } else if line.starts_with("mierus://") {
        parse_mieru_link
    } else if line.starts_with("iwan://") {
        parse_iwan_link
    } else if line.starts_with("anx://") {
        parse_anx_link
    } else if line.starts_with("socks5://")
        || line.starts_with("socks5h://")
        || line.starts_with("socks://")
        || is_http_proxy_link(line)
    {
        parse_plain_proxy_link
    } else {
        return None;
    };
    Some(parser)
}

/// Whether an `http://` or `https://` line is an HTTP proxy link rather than
/// a web address (a subscription or rule list URL): an explicit port, no
/// path, no query besides the link's own fields, and credentials or a
/// `#name`. Other such lines are skipped like lines of unknown schemes.
pub(crate) fn is_http_proxy_link(line: &str) -> bool {
    let Some(rest) = line
        .strip_prefix("http://")
        .or_else(|| line.strip_prefix("https://"))
    else {
        return false;
    };
    let (without_fragment, fragment) = split_once_optional(rest, '#');
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let (host_port, path) = split_once_optional(host_port, '/');
    let has_port = host_port.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty() && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
    });
    let own_query = query.is_none_or(|query| {
        query
            .split('&')
            .filter(|entry| !entry.is_empty())
            .all(|entry| {
                let key = entry.split_once('=').map_or(entry, |(key, _)| key);
                HTTP_PROXY_LINK_FIELDS
                    .iter()
                    .any(|field| key.eq_ignore_ascii_case(field))
            })
    });
    let named = fragment.is_some_and(|fragment| !fragment.trim().is_empty());
    has_port
        && path.is_none_or(str::is_empty)
        && own_query
        && (userinfo.is_some_and(|userinfo| !userinfo.is_empty()) || named)
}

/// The query fields an HTTP proxy link may carry: the TLS server name and
/// certificate check of `https://`, and the AnixOps `via`.
pub(crate) const HTTP_PROXY_LINK_FIELDS: [&str; 6] = [
    "sni",
    "peer",
    "insecure",
    "allowinsecure",
    "skip-cert-verify",
    "via",
];

/// Parses an HTTP or SOCKS5 proxy link: `http://`, `https://` (HTTP over
/// TLS, with `sni` and `insecure`), `socks5://`, `socks5h://` and
/// `socks://`, as `scheme://[user[:password]@]host:port[#name]`. The user
/// and password are percent-decoded; a `socks://` link (v2rayN) may instead
/// carry them base64-encoded as `user:password`.
pub(crate) fn parse_plain_proxy_link(link: &str) -> DomainResult<NodeDescriptor> {
    let (scheme, payload) = link.split_once("://").unwrap_or(("", link));
    let scheme = scheme.to_ascii_lowercase();
    let (protocol, tag, tls, code, protocol_name) = match scheme.as_str() {
        "http" => (
            Protocol::Http,
            "http",
            false,
            SUBSCRIPTION_HTTP_LINK_INVALID_CODE,
            "http proxy",
        ),
        "https" => (
            Protocol::Http,
            "http",
            true,
            SUBSCRIPTION_HTTP_LINK_INVALID_CODE,
            "http proxy",
        ),
        "socks" | "socks5" | "socks5h" => (
            Protocol::Socks,
            "socks",
            false,
            SUBSCRIPTION_SOCKS_LINK_INVALID_CODE,
            "socks",
        ),
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
                "proxy link must start with http://, https://, socks5:// or socks://",
            ))
        }
    };
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} link name is not valid percent encoding"),
            )
        })?
        .filter(|name| !name.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let host_port = strip_share_link_path(host_port);
    let (host, port) = parse_host_port_for(host_port, code, protocol_name)?;
    let (username, password) = match userinfo {
        Some(userinfo) => {
            plain_proxy_link_credentials(userinfo, scheme == "socks", code, protocol_name)?
        }
        None => (None, None),
    };
    let query = parse_share_link_query(query, code, protocol_name)?;
    let server_name = ["sni", "peer"]
        .iter()
        .find_map(|key| query.get(*key))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let insecure = ["insecure", "allowinsecure", "skip-cert-verify"]
        .iter()
        .find_map(|key| query.get(*key))
        .map(|value| parse_share_link_boolean(value, code, "TLS insecure"))
        .transpose()?
        .unwrap_or(false);
    let mut metadata = plain_proxy_metadata(
        PlainProxyFields {
            username,
            password,
            tls,
            server_name,
            insecure,
            ..PlainProxyFields::default()
        },
        &host,
    );
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: format!("{tag}-url"),
    });
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("{tag}-{host_id}-{port}");
    let name = name.unwrap_or_else(|| id.clone());
    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), tag.to_string()],
        metadata,
    })
}

/// The user and password of a proxy link's `user[:password]`, each
/// percent-decoded. With `base64_userinfo` (a `socks://` link), userinfo
/// without `:` that decodes as base64 to `user:password` is read that way.
pub(crate) fn plain_proxy_link_credentials(
    userinfo: &str,
    base64_userinfo: bool,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<(Option<String>, Option<String>)> {
    let invalid = || {
        domain_error(
            code,
            format!("{protocol_name} link credentials are not valid percent encoding"),
        )
    };
    let encoded = base64_userinfo
        .then(|| percent_decode(userinfo).ok())
        .flatten()
        .filter(|userinfo| !userinfo.contains(':'))
        .and_then(|userinfo| decode_base64_text(&userinfo))
        .filter(|decoded| decoded.contains(':'));
    let (username, password) = match encoded {
        Some(decoded) => {
            let (username, password) = split_once_optional(&decoded, ':');
            (username.to_string(), password.map(str::to_string))
        }
        None => {
            let (username, password) = split_once_optional(userinfo, ':');
            (
                percent_decode(username).map_err(|_| invalid())?,
                password
                    .map(percent_decode)
                    .transpose()
                    .map_err(|_| invalid())?,
            )
        }
    };
    Ok((
        Some(username).filter(|username| !username.is_empty()),
        password.filter(|password| !password.is_empty()),
    ))
}

/// The AnixOps subscription line that marks the next link's path
/// (`#anixops:path=trunk`); other `#` lines stay comments.
pub(crate) const ANIXOPS_PATH_MARK: &str = "anixops:path=";

/// Path kinds a mark may carry: 1-32 of `[a-z0-9_-]`, so a later kind
/// passes through to clients that know it.
pub(crate) fn is_path_kind(kind: &str) -> bool {
    (1..=32).contains(&kind.len())
        && kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// Takes the AnixOps `via` query field (the name of the node a link connects
/// through, like a sing-box `detour`) off a share link, so the protocol's own
/// parser never sees it. A `vmess://` link carries it after its base64 body.
pub(crate) fn take_link_via(line: &str) -> DomainResult<(String, Option<String>)> {
    let (without_fragment, fragment) = split_once_optional(line, '#');
    let (main, query) = split_once_optional(without_fragment, '?');
    let Some(query) = query else {
        return Ok((line.to_string(), None));
    };
    let mut via = None;
    let mut kept = Vec::new();
    for entry in query.split('&') {
        let key = entry.split_once('=').map_or(entry, |(key, _)| key);
        if key.eq_ignore_ascii_case("via") {
            let value = entry.split_once('=').map_or("", |(_, value)| value);
            let value = percent_decode(value).map_err(|_| {
                domain_error(
                    SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
                    "share link via is not valid percent encoding",
                )
            })?;
            via = Some(value.trim().to_string()).filter(|value| !value.is_empty());
        } else {
            kept.push(entry);
        }
    }
    if via.is_none() {
        return Ok((line.to_string(), None));
    }
    let mut rebuilt = main.to_string();
    if !kept.is_empty() {
        rebuilt.push('?');
        rebuilt.push_str(&kept.join("&"));
    }
    if let Some(fragment) = fragment {
        rebuilt.push('#');
        rebuilt.push_str(fragment);
    }
    Ok((rebuilt, via))
}

/// Parses an AnixOps Panabit iWAN link:
/// `iwan://user:password@host:port?mtu=1400&encrypt=1#name`.
pub(crate) fn parse_iwan_link(link: &str) -> DomainResult<NodeDescriptor> {
    let invalid = |message: &str| domain_error(SUBSCRIPTION_IWAN_LINK_INVALID_CODE, message);
    let payload = link
        .strip_prefix("iwan://")
        .ok_or_else(|| invalid("iwan link must start with iwan://"))?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = main_without_query
        .rsplit_once('@')
        .ok_or_else(|| invalid("iwan link must contain a login and an endpoint"))?;
    let host_port = strip_share_link_path(host_port);
    let (username, password) = userinfo
        .split_once(':')
        .ok_or_else(|| invalid("iwan link login must be username:password"))?;
    let decode = |value: &str| percent_decode(value).unwrap_or_else(|_| value.to_string());
    let username = required_trimmed(
        decode(username),
        SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
        "iwan username cannot be empty",
    )?;
    let password = required_trimmed(
        decode(password),
        SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
        "iwan password cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(host_port, SUBSCRIPTION_IWAN_LINK_INVALID_CODE, "iwan")?;
    let query = parse_share_link_query(query, SUBSCRIPTION_IWAN_LINK_INVALID_CODE, "iwan")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("iwan-{host_id}-{port}");
    let name = name.unwrap_or_else(|| id.clone());

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
    if let Some(mtu) = query.get("mtu").filter(|mtu| !mtu.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_IWAN_MTU.to_string(),
            value: mtu.trim().to_string(),
        });
    }
    if let Some(encrypt) = query.get("encrypt") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_IWAN_ENCRYPT.to_string(),
            value: parse_share_link_boolean(
                encrypt,
                SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
                "iwan encrypt",
            )?
            .to_string(),
        });
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "iwan-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Iwan,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "iwan".to_string()],
        metadata,
    })
}

/// Parses an AnixOps ANX-A link:
/// `anx://<user key>@host:port?sni=<name>&pk=<server public key>&alpn=h2,http/1.1&fp=chrome#name`.
/// The user key is 64 hex digits; `pk` is the server's public key text. `sni` is
/// optional: leave it out and the client sends no SNI.
pub(crate) fn parse_anx_link(link: &str) -> DomainResult<NodeDescriptor> {
    let invalid = |message: &str| domain_error(SUBSCRIPTION_ANX_LINK_INVALID_CODE, message);
    let payload = link
        .strip_prefix("anx://")
        .ok_or_else(|| invalid("anx link must start with anx://"))?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (user_key, host_port) = main_without_query
        .rsplit_once('@')
        .ok_or_else(|| invalid("anx link must contain a user key and an endpoint"))?;
    let host_port = strip_share_link_path(host_port);
    let user_key = required_trimmed(
        user_key.to_string(),
        SUBSCRIPTION_ANX_LINK_INVALID_CODE,
        "anx user key cannot be empty",
    )?;
    if user_key.len() != 64 || !user_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("anx user key must be 64 hex digits"));
    }
    let (host, port) = parse_host_port_for(host_port, SUBSCRIPTION_ANX_LINK_INVALID_CODE, "anx")?;
    let query = parse_share_link_query(query, SUBSCRIPTION_ANX_LINK_INVALID_CODE, "anx")?;
    let public_key = required_trimmed(
        query.get("pk").cloned().unwrap_or_default(),
        SUBSCRIPTION_ANX_LINK_INVALID_CODE,
        "anx link needs pk, the server public key",
    )?;
    // `sni` is optional: without it the client sends no SNI, for servers that
    // accept connections to their IP address directly.
    let server_name = query
        .get("sni")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("anx-{host_id}-{port}");
    let name = name.unwrap_or_else(|| id.clone());

    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_ANX_USER_KEY.to_string(),
            value: user_key,
        },
        MetadataEntry {
            key: NODE_METADATA_ANX_PUBLIC_KEY.to_string(),
            value: public_key,
        },
    ];
    if let Some(server_name) = server_name {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_SERVER_NAME.to_string(),
            value: server_name,
        });
    }
    for (query_key, metadata_key) in [
        ("alpn", NODE_METADATA_ANX_ALPN),
        ("fp", NODE_METADATA_ANX_FINGERPRINT),
    ] {
        if let Some(value) = query
            .get(query_key)
            .filter(|value| !value.trim().is_empty())
        {
            metadata.push(MetadataEntry {
                key: metadata_key.to_string(),
                value: value.trim().to_string(),
            });
        }
    }
    // `jacket` picks the outer shape (auto, wg, bare or a2); `wg_port` is the
    // UDP port of the wg jacket, which `jacket=wg` needs; `bare_port` is the
    // TCP port of the bare jacket, which `jacket=bare` needs.
    let jacket = query
        .get("jacket")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(jacket) = &jacket {
        if !matches!(jacket.as_str(), "auto" | "wg" | "bare" | "a2") {
            return Err(invalid("anx jacket must be auto, wg, bare or a2"));
        }
    }
    let wg_port = match query.get("wg_port").map(|value| value.trim()) {
        None | Some("") => None,
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => return Err(invalid("anx wg_port must be a port number")),
        },
    };
    if jacket.as_deref() == Some("wg") && wg_port.is_none() {
        return Err(invalid("anx jacket wg needs wg_port"));
    }
    let bare_port = match query.get("bare_port").map(|value| value.trim()) {
        None | Some("") => None,
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => return Err(invalid("anx bare_port must be a port number")),
        },
    };
    if jacket.as_deref() == Some("bare") && bare_port.is_none() {
        return Err(invalid("anx jacket bare needs bare_port"));
    }
    if let Some(jacket) = jacket {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_JACKET.to_string(),
            value: jacket,
        });
    }
    if let Some(port) = wg_port {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_WG_PORT.to_string(),
            value: port.to_string(),
        });
    }
    if let Some(port) = bare_port {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_BARE_PORT.to_string(),
            value: port.to_string(),
        });
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "anx-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Anx,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "anx".to_string()],
        metadata,
    })
}

/// A `port=` / `protocol=` pair of a simple share link.
pub(crate) struct MieruBinding {
    pub(crate) port: String,
    pub(crate) protocol: String,
}

/// `P` or `A-B` as (first port, range text when it is a range).
pub(crate) fn parse_mieru_port_binding(value: &str) -> DomainResult<(u16, Option<String>)> {
    let invalid = || {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru port must be a port or a port range",
        )
    };
    let value = value.trim();
    let parse = |text: &str| {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(invalid)
    };
    match value.split_once('-') {
        None => Ok((parse(value)?, None)),
        Some((low, high)) => {
            let (low, high) = (parse(low)?, parse(high)?);
            if low > high {
                return Err(invalid());
            }
            Ok((low, Some(format!("{low}-{high}"))))
        }
    }
}

/// Parses the official simple share link
/// (`mierus://user:pass@host?port=P&protocol=TCP&...`, `port`/`protocol`
/// repeating in pairs) and the older `mierus://user:pass@host:port?...` form.
pub(crate) fn parse_mieru_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("mierus://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link must start with mierus://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru link name is not valid percent encoding",
            )
        })?
        .filter(|value| !value.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link must contain credentials and endpoint",
        )
    })?;
    let host_port = strip_share_link_path(host_port);
    let (username, password) = userinfo.split_once(':').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link credentials must contain username and password",
        )
    })?;
    let username = required_trimmed(
        percent_decode(username).map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru username is not valid percent encoding",
            )
        })?,
        SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
        "Mieru username cannot be empty",
    )?;
    let password = required_trimmed(
        percent_decode(password).map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru password is not valid percent encoding",
            )
        })?,
        SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
        "Mieru password cannot be empty",
    )?;
    let fields = parse_share_link_query(query, SUBSCRIPTION_MIERU_LINK_INVALID_CODE, "Mieru")?;
    // `port` and `protocol` repeat, so read them in order from the raw query.
    let mut ports = Vec::new();
    let mut protocols = Vec::new();
    for entry in query.unwrap_or_default().split('&') {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        let value = percent_decode(value).unwrap_or_default();
        match key.trim().to_ascii_lowercase().as_str() {
            "port" => ports.push(value),
            "protocol" => protocols.push(value),
            _ => {}
        }
    }
    let mut transport = "TCP".to_string();
    let mut port_range = fields
        .get("port_range")
        .or_else(|| fields.get("ports"))
        .map(|value| {
            required_trimmed(
                value.clone(),
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru port range cannot be empty",
            )
        })
        .transpose()?;
    let (host, port) = if ports.is_empty() {
        parse_host_port_for(host_port, SUBSCRIPTION_MIERU_LINK_INVALID_CODE, "Mieru")?
    } else {
        if ports.len() != protocols.len() {
            return Err(domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru port and protocol must appear in pairs",
            ));
        }
        let bindings: Vec<MieruBinding> = ports
            .into_iter()
            .zip(protocols)
            .map(|(port, protocol)| MieruBinding {
                port,
                protocol: protocol.trim().to_ascii_uppercase(),
            })
            .collect();
        let binding = bindings
            .iter()
            .find(|binding| binding.protocol == "TCP")
            .unwrap_or(&bindings[0]);
        if binding.protocol != "TCP" && binding.protocol != "UDP" {
            return Err(domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru protocol must be TCP or UDP",
            ));
        }
        transport = binding.protocol.clone();
        let (port, range) = parse_mieru_port_binding(&binding.port)?;
        if range.is_some() {
            port_range = range;
        }
        let host = host_port
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host_port);
        let host = required_trimmed(
            host.to_string(),
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru host cannot be empty",
        )?;
        (host, port)
    };
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() { "host" } else { &host_id };
    let id = format!("mieru-{host_id}-{port}");
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
            value: transport,
        },
    ];
    if let Some(value) = port_range {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_PORT_RANGE.to_string(),
            value,
        });
    }
    if let Some(value) = fields.get("mtu") {
        let value = value.parse::<u16>().map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru mtu must be an unsigned 16-bit integer",
            )
        })?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_MTU.to_string(),
            value: value.to_string(),
        });
    }
    if let Some(value) = fields
        .get("multiplexing")
        .or_else(|| fields.get("multiplex"))
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_MULTIPLEXING.to_string(),
            value: parse_mieru_multiplexing(value)?.to_string(),
        });
    }
    for (keys, metadata_key) in [
        (
            ["handshake_mode", "handshake-mode", "handshake"],
            NODE_METADATA_MIERU_HANDSHAKE_MODE,
        ),
        (
            ["traffic_pattern", "traffic-pattern", "traffic"],
            NODE_METADATA_MIERU_TRAFFIC_PATTERN,
        ),
    ] {
        if let Some(value) = keys.iter().find_map(|key| fields.get(*key)) {
            metadata.push(MetadataEntry {
                key: metadata_key.to_string(),
                value: required_trimmed(
                    value.clone(),
                    SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                    "Mieru option cannot be empty",
                )?,
            });
        }
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "mierus-url".to_string(),
    });
    Ok(NodeDescriptor {
        id,
        name: name.unwrap_or_else(|| format!("Mieru {host}")),
        protocol: Protocol::Mieru,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "mieru".to_string()],
        metadata,
    })
}

/// A boolean, or a `MULTIPLEXING_*` level (anything but `OFF` is on).
pub(crate) fn parse_mieru_multiplexing(value: &str) -> DomainResult<bool> {
    match normalized_token(value).as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" | "multiplexing_off" => Ok(false),
        "multiplexing_low" | "multiplexing_middle" | "multiplexing_high" => Ok(true),
        _ => Err(domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru multiplexing must be a boolean or a MULTIPLEXING_ level",
        )),
    }
}

pub(crate) fn parse_shadowsocks_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("ss://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks link must start with ss://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    // SIP003 `plugin=<name>;<options>`; only the name is kept, the options
    // can hold passwords. Other query fields (`outline=1`, ...) do not
    // change the connection and are not read.
    let plugin = shadowsocks_plugin_entry(
        query
            .into_iter()
            .flat_map(|query| query.split('&'))
            .find_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                key.trim().eq_ignore_ascii_case("plugin").then(|| {
                    let value = percent_decode(value).unwrap_or_else(|_| value.to_string());
                    let (name, _) = split_once_optional(&value, ';');
                    name.to_string()
                })
            }),
    );

    let (credentials, host_port) = match main_without_query.rsplit_once('@') {
        // SIP002: `ss://userinfo@host:port[/][?query]`.
        Some((userinfo, host_port)) => (
            shadowsocks_sip002_credentials(userinfo),
            host_port.to_string(),
        ),
        // Legacy: `ss://base64(method:password@host:port)`, the credentials
        // in plain text inside the base64.
        None => {
            let decoded =
                decode_legacy_shadowsocks_payload(main_without_query).ok_or_else(|| {
                    domain_error(
                        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
                        "shadowsocks link payload is not valid base64",
                    )
                })?;
            let (userinfo, host_port) = decoded.rsplit_once('@').ok_or_else(|| {
                domain_error(
                    SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
                    "shadowsocks link must contain credentials and endpoint",
                )
            })?;
            let credentials = decode_base64_text(userinfo).unwrap_or_else(|| userinfo.to_string());
            let credentials = credentials
                .split_once(':')
                .map(|(method, password)| (method.to_string(), password.to_string()));
            (credentials, host_port.to_string())
        }
    };
    let (method, password) = credentials.ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks credentials must contain method and password",
        )
    })?;
    let method = required_trimmed(
        method,
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks method cannot be empty",
    )?;
    let password = required_trimmed(
        password,
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks password cannot be empty",
    )?;
    // SIP002 puts a `/` between the port and the query (`@host:8388/?plugin=`).
    let host_port = strip_share_link_path(&host_port);
    let (host, port) = parse_host_port_for(
        host_port,
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("ss-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Shadowsocks,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "ss".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                value: method,
            },
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                value: password,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "ss-url".to_string(),
            },
        ]
        .into_iter()
        .chain(plugin)
        .collect(),
    })
}

/// SIP002 userinfo as `(method, password)`: either `method:password`
/// percent-encoded (required for the 2022 methods, whose base64 keys hold
/// `+`, `/` and `=`), or base64url of `method:password`, whose `=` padding
/// may itself be percent-encoded. `%XX` only: `+` stays `+`. A value that
/// is not valid percent encoding (a raw `50%off`) is kept as written.
pub(crate) fn shadowsocks_sip002_credentials(userinfo: &str) -> Option<(String, String)> {
    let decode = |value: &str| percent_decode(value).unwrap_or_else(|_| value.to_string());
    if let Some((method, password)) = userinfo.split_once(':') {
        return Some((decode(method), decode(password)));
    }
    let userinfo = decode(userinfo);
    let credentials = decode_base64_text(&userinfo).unwrap_or(userinfo);
    let (method, password) = credentials.split_once(':')?;
    Some((method.to_string(), password.to_string()))
}

/// Decodes a legacy `ss://base64(method:password@host:port)` payload,
/// also when a SIP002-style `/` follows it (`ss://<base64>/?plugin=`).
/// `/` is a base64 character, so the payload is first decoded as written
/// and the `/` is dropped only when that does not give a usable endpoint.
pub(crate) fn decode_legacy_shadowsocks_payload(payload: &str) -> Option<String> {
    let decode = |payload: &str| {
        decode_base64_text(payload).filter(|decoded| {
            decoded.rsplit_once('@').is_some_and(|(_, host_port)| {
                parse_host_port_for(
                    strip_share_link_path(host_port),
                    SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
                    "shadowsocks",
                )
                .is_ok()
            })
        })
    };
    decode(payload)
        .or_else(|| payload.strip_suffix('/').and_then(decode))
        // Neither gives an endpoint: keep the decoded text so the caller
        // reports what is wrong with it.
        .or_else(|| decode_base64_text(payload))
}

pub(crate) fn parse_trojan_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("trojan://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must start with trojan://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (password, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must contain password and endpoint",
        )
    })?;
    let host_port = strip_share_link_path(host_port);
    let password = percent_decode(password).unwrap_or_else(|_| password.to_string());
    let password = required_trimmed(
        password,
        SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
        "trojan password cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_TROJAN_LINK_INVALID_CODE, "trojan")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("trojan-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    let query = parse_share_link_query(query, SUBSCRIPTION_TROJAN_LINK_INVALID_CODE, "trojan")?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
        value: password,
    }];
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        true,
        SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
        "trojan",
    )?;
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "trojan-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Trojan,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "trojan".to_string()],
        metadata,
    })
}

pub(crate) fn parse_vless_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vless://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must start with vless://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (uuid, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must contain uuid and endpoint",
        )
    })?;
    let host_port = strip_share_link_path(host_port);
    let uuid = percent_decode(uuid).unwrap_or_else(|_| uuid.to_string());
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
        "vless uuid cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_VLESS_LINK_INVALID_CODE, "vless")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vless-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    let query = parse_share_link_query(query, SUBSCRIPTION_VLESS_LINK_INVALID_CODE, "vless")?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_VLESS_UUID.to_string(),
        value: uuid,
    }];
    if let Some(flow) = query.get("flow").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VLESS_FLOW.to_string(),
            value: flow.trim().to_string(),
        });
    }
    if let Some(encryption) = query
        .get("encryption")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "none")
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VLESS_ENCRYPTION.to_string(),
            value: encryption.to_string(),
        });
    }
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        false,
        SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
        "vless",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vless,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vless".to_string()],
        metadata: {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vless-url".to_string(),
            });
            metadata
        },
    })
}

pub(crate) fn parse_vmess_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vmess://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link must start with vmess://",
        )
    })?;
    let decoded = decode_base64_text(payload).ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid base64",
        )
    })?;
    let value = serde_json::from_str::<serde_json::Value>(&decoded).map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid json",
        )
    })?;
    let uuid = required_json_text_field(
        &value,
        "id",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess uuid cannot be empty",
    )?;
    let host = required_json_text_field(
        &value,
        "add",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess host cannot be empty",
    )?;
    let port = required_json_text_field(
        &value,
        "port",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port must be between 1 and 65535",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vmess-{}-{port}", host_id);
    let name = optional_json_text_field(&value, "ps").unwrap_or_else(|| id.clone());

    let mut query = BTreeMap::new();
    for (json_key, query_key) in [
        ("tls", "tls"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("allowInsecure", "allowinsecure"),
        ("insecure", "insecure"),
        ("pcs", "pcs"),
        ("fp", "fp"),
        ("pbk", "pbk"),
        ("sid", "sid"),
        ("net", "type"),
        ("host", "host"),
        ("path", "path"),
        ("serviceName", "servicename"),
        ("mode", "mode"),
        ("extra", "extra"),
    ] {
        if let Some(field) = optional_json_text_field(&value, json_key) {
            query.insert(query_key.to_string(), field);
        }
    }
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_VMESS_UUID.to_string(),
        value: uuid,
    }];
    if let Some(security) = optional_json_text_field(&value, "scy") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VMESS_SECURITY.to_string(),
            value: security,
        });
    }
    if let Some(alter_id) = optional_json_text_field(&value, "aid") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
            value: alter_id,
        });
    }
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        false,
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vmess,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vmess".to_string()],
        metadata: {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vmess-url".to_string(),
            });
            metadata
        },
    })
}

pub(crate) fn parse_hysteria2_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link
        .strip_prefix("hysteria2://")
        .or_else(|| link.strip_prefix("hy2://"))
        .ok_or_else(|| {
            domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 link must start with hysteria2:// or hy2://",
            )
        })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2",
        QuicAuthority::Hysteria2,
    )?;
    let password = required_trimmed(
        parsed.userinfo.clone(),
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2 password cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
        value: password,
    }];
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
    )?;
    // Port hopping is written in the authority (`host:443,5000-6000`, the
    // official URI format) or as `mport=`; both together are merged, the
    // authority's entries first.
    let mut server_ports: Vec<String> = parsed
        .server_ports
        .as_deref()
        .into_iter()
        .flat_map(|ports| ports.split(','))
        .map(str::to_string)
        .collect();
    if let Some(mport) = parsed.query.get("mport") {
        for range in normalize_hysteria2_server_port_ranges(
            vec![mport.to_string()],
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        )? {
            if !server_ports.contains(&range) {
                server_ports.push(range);
            }
        }
    }
    if !server_ports.is_empty() {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
            value: server_ports.join(","),
        });
    }
    if let Some(kind) = parsed.query.get("obfs") {
        let kind = normalized_token(kind);
        if !matches!(kind.as_str(), "salamander" | "gecko") {
            return Err(domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 obfs must be salamander or gecko",
            ));
        }
        let password = required_query_value(
            &parsed.query,
            "obfs-password",
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
            "hysteria2 obfs-password cannot be empty when obfs is configured",
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
            if let Some(value) = parsed.query.get("minpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
            if let Some(value) = parsed.query.get("maxpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
        }
    }

    Ok(quic_node_descriptor(
        "hysteria2",
        Protocol::Hysteria2,
        parsed,
        metadata,
    ))
}

pub(crate) fn parse_tuic_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("tuic://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic link must start with tuic://",
        )
    })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
        "tuic",
        QuicAuthority::HostPort,
    )?;
    let (uuid, password) = parsed
        .userinfo
        .split_once(':')
        .map(|(uuid, password)| (uuid.to_string(), Some(password.to_string())))
        .unwrap_or_else(|| (parsed.userinfo.clone(), None));
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
        "tuic uuid cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_TUIC_UUID.to_string(),
        value: uuid,
    }];
    if let Some(password) = password {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_PASSWORD.to_string(),
            value: password,
        });
    }
    if let Some(congestion_control) = parsed.query.get("congestion_control") {
        let congestion_control = required_trimmed(
            congestion_control.to_string(),
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic congestion_control cannot be empty",
        )?;
        if !matches!(congestion_control.as_str(), "cubic" | "new_reno" | "bbr") {
            return Err(domain_error(
                SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
                "tuic congestion_control must be cubic, new_reno, or bbr",
            ));
        }
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
            value: congestion_control,
        });
    }
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
    )?;

    Ok(quic_node_descriptor(
        "tuic",
        Protocol::Tuic,
        parsed,
        metadata,
    ))
}

pub(crate) fn parse_wireguard_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("wireguard://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
            "wireguard link must start with wireguard://",
        )
    })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard",
        QuicAuthority::HostPort,
    )?;
    let private_key = validate_wireguard_key(
        &parsed.userinfo,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "private key",
    )?;
    let peer_public_key = required_query_value(
        &parsed.query,
        "publickey",
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard publickey is required",
    )?;
    let peer_public_key = validate_wireguard_key(
        &peer_public_key,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "publickey",
    )?;
    let local_address = required_query_value(
        &parsed.query,
        "address",
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard address is required",
    )?;
    let local_address =
        normalize_wireguard_addresses(&local_address, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?;
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PRIVATE_KEY.to_string(),
            value: private_key,
        },
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY.to_string(),
            value: peer_public_key,
        },
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_LOCAL_ADDRESS.to_string(),
            value: local_address,
        },
    ];
    if let Some(value) = parsed.query.get("presharedkey") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PRE_SHARED_KEY.to_string(),
            value: validate_wireguard_key(
                value,
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "presharedkey",
            )?,
        });
    }
    if let Some(value) = parsed.query.get("mtu") {
        let mtu = value.trim().parse::<u16>().map_err(|_| {
            domain_error(
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "wireguard mtu must be an unsigned 16-bit integer",
            )
        })?;
        if mtu == 0 {
            return Err(domain_error(
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "wireguard mtu must be greater than zero",
            ));
        }
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_MTU.to_string(),
            value: mtu.to_string(),
        });
    }
    if let Some(value) = parsed.query.get("allowedips") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_ALLOWED_IPS.to_string(),
            value: normalize_wireguard_addresses(value, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?,
        });
    }
    if let Some(value) = parsed.query.get("reserved") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_RESERVED.to_string(),
            value: normalize_wireguard_reserved(value, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?,
        });
    }
    Ok(quic_node_descriptor(
        "wireguard",
        Protocol::WireGuard,
        parsed,
        metadata,
    ))
}

pub(crate) fn validate_wireguard_key(
    value: &str,
    code: &'static str,
    field: &'static str,
) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(domain_error(
            code,
            format!("wireguard {field} cannot be empty"),
        ));
    }
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(value).ok());
    if !matches!(decoded, Some(ref bytes) if bytes.len() == 32) {
        return Err(domain_error(
            code,
            format!("wireguard {field} must be a base64-encoded 32-byte key"),
        ));
    }
    Ok(value.to_string())
}

/// Three reserved header bytes as `a,b,c` decimals (`reserved=1,2,3`).
pub(crate) fn normalize_wireguard_reserved(
    value: &str,
    code: &'static str,
) -> DomainResult<String> {
    let bytes = value
        .split(',')
        .map(|byte| byte.trim().parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| domain_error(code, "wireguard reserved must be three bytes"))?;
    if bytes.len() != 3 {
        return Err(domain_error(code, "wireguard reserved must be three bytes"));
    }
    Ok(format!("{},{},{}", bytes[0], bytes[1], bytes[2]))
}

pub(crate) fn normalize_wireguard_addresses(
    value: &str,
    code: &'static str,
) -> DomainResult<String> {
    let addresses = value
        .split(',')
        .map(str::trim)
        .map(|address| {
            let (host, prefix) = address.split_once('/').ok_or_else(|| {
                domain_error(code, "wireguard address entries must use CIDR notation")
            })?;
            let host = host.parse::<std::net::IpAddr>().map_err(|_| {
                domain_error(
                    code,
                    "wireguard address entries must contain valid IP addresses",
                )
            })?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                domain_error(code, "wireguard address prefixes must be unsigned integers")
            })?;
            let maximum_prefix = match host {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            if prefix > maximum_prefix {
                return Err(domain_error(
                    code,
                    "wireguard address prefix exceeds the address family limit",
                ));
            }
            Ok(format!("{host}/{prefix}"))
        })
        .collect::<DomainResult<Vec<_>>>()?;
    if addresses.is_empty() {
        return Err(domain_error(code, "wireguard address cannot be empty"));
    }
    Ok(addresses.join(","))
}

#[derive(Debug)]
pub(crate) struct ParsedQuicShareLink {
    pub(crate) userinfo: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Normalized port-hopping list from a Hysteria2 authority.
    pub(crate) server_ports: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) query: BTreeMap<String, String>,
}

/// How a QUIC-family share link writes its `host:port`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum QuicAuthority {
    /// `host:port`, the port required.
    HostPort,
    /// The Hysteria2 URI format: the port defaults to 443 and may be a
    /// port-hopping list.
    Hysteria2,
}

pub(crate) fn parse_quic_share_link(
    payload: &str,
    code: &'static str,
    protocol_name: &'static str,
    authority_format: QuicAuthority,
) -> DomainResult<ParsedQuicShareLink> {
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} link name is not valid percent encoding"),
            )
        })?
        .filter(|name| !name.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').ok_or_else(|| {
        domain_error(
            code,
            format!("{protocol_name} link must contain credentials and endpoint"),
        )
    })?;
    let userinfo = percent_decode(userinfo).map_err(|_| {
        domain_error(
            code,
            format!("{protocol_name} link credentials are not valid percent encoding"),
        )
    })?;
    let host_port = strip_share_link_path(host_port);
    let (host, port, server_ports) = match authority_format {
        QuicAuthority::HostPort => {
            let (host, port) = parse_host_port_for(host_port, code, protocol_name)?;
            (host, port, None)
        }
        QuicAuthority::Hysteria2 => parse_hysteria2_authority(host_port, code)?,
    };
    let query = parse_share_link_query(query, code, protocol_name)?;
    Ok(ParsedQuicShareLink {
        userinfo,
        host,
        port,
        server_ports,
        name,
        query,
    })
}

pub(crate) fn parse_share_link_query(
    query: Option<&str>,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let Some(query) = query else {
        return Ok(values);
    };
    for entry in query.split('&') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            domain_error(
                code,
                format!("{protocol_name} query fields must use key=value"),
            )
        })?;
        let key = percent_decode(key).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query key is not valid percent encoding"),
            )
        })?;
        let value = percent_decode(value).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query value is not valid percent encoding"),
            )
        })?;
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(domain_error(
                code,
                format!("{protocol_name} query key cannot be empty"),
            ));
        }
        values.insert(key, value);
    }
    Ok(values)
}

pub(crate) fn quic_node_descriptor(
    protocol_tag: &'static str,
    protocol: Protocol,
    parsed: ParsedQuicShareLink,
    mut metadata: Metadata,
) -> NodeDescriptor {
    let host_id = sanitize_identifier(&parsed.host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("{protocol_tag}-{host_id}-{}", parsed.port);
    let name = parsed.name.unwrap_or_else(|| id.clone());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: format!("{protocol_tag}-url"),
    });
    NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint {
            host: parsed.host,
            port: parsed.port,
        },
        tags: vec!["subscription".to_string(), protocol_tag.to_string()],
        metadata,
    }
}

pub(crate) fn append_query_tls_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    host: &str,
    code: &'static str,
) -> DomainResult<()> {
    let server_name = query
        .get("sni")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| host.to_string());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
        value: server_name,
    });
    let insecure = query
        .get("insecure")
        .or_else(|| query.get("allowinsecure"))
        .or_else(|| query.get("allow_insecure"))
        .map(|value| parse_share_link_boolean(value, code, "TLS insecure"))
        .transpose()?
        .unwrap_or(false);
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_INSECURE.to_string(),
        value: insecure.to_string(),
    });
    if let Some(alpn) = query.get("alpn") {
        let alpn = split_share_link_list(alpn, code, "TLS alpn")?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    // Hysteria2 `pinSHA256` and Xray `pcs` both pin the whole certificate.
    let mut pins = Vec::new();
    for key in ["pinsha256", "pcs"] {
        if let Some(value) = query.get(key) {
            pins.extend(split_share_link_list(
                value,
                code,
                "TLS certificate sha256",
            )?);
        }
    }
    metadata.extend(certificate_pin_metadata(&pins, &[]));
    Ok(())
}

/// Pin entries for certificate digests (`tls.certificate_sha256`, kept in
/// lowercase hex) and public key digests (`tls.certificate_public_key_sha256`,
/// kept in base64), each written in hex or base64. A value that is not a
/// SHA-256 digest is kept as written, so the node import reports that node as
/// unsupported instead of running it without its pin, and the rest of the
/// subscription still imports.
pub(crate) fn certificate_pin_metadata(certificate: &[String], public_key: &[String]) -> Metadata {
    let mut metadata = Vec::new();
    metadata.extend(pin_metadata_entry(
        NODE_METADATA_TLS_CERTIFICATE_SHA256,
        certificate,
        certificate_pin::to_hex,
    ));
    metadata.extend(pin_metadata_entry(
        NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256,
        public_key,
        certificate_pin::to_base64,
    ));
    metadata
}

pub(crate) fn pin_metadata_entry(
    key: &str,
    pins: &[String],
    spell: fn(&certificate_pin::Sha256Digest) -> String,
) -> Option<MetadataEntry> {
    let mut values: Vec<String> = Vec::new();
    for pin in pins
        .iter()
        .map(|pin| pin.trim())
        .filter(|pin| !pin.is_empty())
    {
        let value =
            certificate_pin::parse(pin).map_or_else(|| pin.to_string(), |digest| spell(&digest));
        if !values.contains(&value) {
            values.push(value);
        }
    }
    (!values.is_empty()).then(|| MetadataEntry {
        key: key.to_string(),
        value: values.join(","),
    })
}

/// The pin entries of a Clash, Surge, Loon or Quantumult X proxy, whose
/// formats name one certificate digest and one public key digest at most.
pub(crate) fn proxy_line_pin_metadata(
    certificate: Option<String>,
    public_key: Option<String>,
) -> Metadata {
    certificate_pin_metadata(
        &certificate.into_iter().collect::<Vec<_>>(),
        &public_key.into_iter().collect::<Vec<_>>(),
    )
}

pub(crate) fn append_v2ray_share_link_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    host: &str,
    default_tls_enabled: bool,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<()> {
    let security = query
        .get("security")
        .or_else(|| query.get("tls"))
        .map(|value| value.trim().to_ascii_lowercase());
    let (tls_enabled, reality_enabled) = match security.as_deref() {
        None | Some("") => (default_tls_enabled, false),
        Some("tls") => (true, false),
        Some("reality") => (true, true),
        Some("none") => (false, false),
        Some(_) => {
            return Err(domain_error(
                code,
                format!("{protocol_name} security must be none, tls, or reality"),
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_ENABLED.to_string(),
        value: tls_enabled.to_string(),
    });
    if tls_enabled {
        append_query_tls_metadata(metadata, query, host, code)?;
        if let Some(fingerprint) = query.get("fp").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_UTLS_FINGERPRINT.to_string(),
                value: fingerprint.trim().to_string(),
            });
        }
    }
    if reality_enabled {
        let public_key = required_query_value(
            query,
            "pbk",
            code,
            "reality public key cannot be empty when security=reality",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_REALITY_PUBLIC_KEY.to_string(),
            value: public_key,
        });
        if let Some(short_id) = query.get("sid").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_REALITY_SHORT_ID.to_string(),
                value: short_id.trim().to_string(),
            });
        }
    }
    append_v2ray_share_link_transport_metadata(metadata, query, code, protocol_name)
}

pub(crate) fn append_v2ray_share_link_transport_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<()> {
    let Some(raw_type) = query.get("type") else {
        return Ok(());
    };
    let kind = match normalized_token(raw_type).as_str() {
        "" | "tcp" | "raw" | "none" => return Ok(()),
        "ws" | "websocket" => "ws",
        "grpc" => "grpc",
        "http" | "h2" => "http",
        "httpupgrade" | "http_upgrade" => "httpupgrade",
        "quic" => "quic",
        "xhttp" | "splithttp" => "xhttp",
        _ => {
            return Err(domain_error(
                code,
                format!(
                    "{protocol_name} transport must be tcp, ws, grpc, http, httpupgrade, quic, or xhttp"
                ),
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_V2RAY_TRANSPORT_TYPE.to_string(),
        value: kind.to_string(),
    });
    if let Some(host) = query.get("host").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_HOST.to_string(),
            value: split_share_link_list(host, code, "transport host")?.join(","),
        });
    }
    if let Some(path) = query.get("path").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_PATH.to_string(),
            value: path.trim().to_string(),
        });
    }
    if let Some(service_name) = query
        .get("servicename")
        .or_else(|| query.get("service_name"))
        .filter(|value| !value.trim().is_empty())
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME.to_string(),
            value: service_name.trim().to_string(),
        });
    }
    if kind == "xhttp" {
        if let Some(mode) = query.get("mode").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_V2RAY_TRANSPORT_MODE.to_string(),
                value: mode.trim().to_string(),
            });
        }
        if let Some(extra) = query.get("extra").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_V2RAY_TRANSPORT_EXTRA.to_string(),
                value: extra.trim().to_string(),
            });
        }
    }
    Ok(())
}

pub(crate) fn parse_share_link_boolean(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" | "" => Ok(false),
        _ => Err(domain_error(
            code,
            format!("{field_name} must be 0, 1, false, or true"),
        )),
    }
}

pub(crate) fn split_share_link_list(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<Vec<String>> {
    let values = value
        .split(',')
        .map(|value| {
            required_trimmed(
                value.to_string(),
                code,
                format!("{field_name} cannot be empty"),
            )
        })
        .collect::<DomainResult<Vec<_>>>()?;
    if values.is_empty() {
        return Err(domain_error(code, format!("{field_name} cannot be empty")));
    }
    Ok(values)
}

pub(crate) fn required_query_value(
    query: &BTreeMap<String, String>,
    key: &'static str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    query
        .get(key)
        .cloned()
        .ok_or_else(|| domain_error(code, message))
        .and_then(|value| required_trimmed(value, code, message))
}

pub(crate) fn normalize_hysteria2_server_port_range(
    value: String,
    code: &'static str,
) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 server port range cannot be empty")?;
    let Some((start, end)) = value.split_once(':').or_else(|| value.split_once('-')) else {
        let port = parse_hysteria2_port(&value, code)?;
        return Ok(port.to_string());
    };
    let start = parse_hysteria2_port(start, code)?;
    let end = parse_hysteria2_port(end, code)?;
    if start > end {
        return Err(domain_error(
            code,
            "hysteria2 server port range start cannot exceed end",
        ));
    }
    Ok(format!("{start}:{end}"))
}

pub(crate) fn normalize_hysteria2_server_port_ranges(
    values: Vec<String>,
    code: &'static str,
) -> DomainResult<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        for range in value.split(',') {
            normalized.push(normalize_hysteria2_server_port_range(
                range.to_string(),
                code,
            )?);
        }
    }
    if normalized.is_empty() {
        return Err(domain_error(
            code,
            "hysteria2 server port ranges cannot be empty",
        ));
    }
    Ok(normalized)
}

pub(crate) fn hysteria2_server_port_range_start(
    value: &str,
    code: &'static str,
) -> DomainResult<u16> {
    let start = value
        .split_once(':')
        .map(|(start, _)| start)
        .unwrap_or(value);
    parse_hysteria2_port(start, code)
}

pub(crate) fn parse_hysteria2_port(value: &str, code: &'static str) -> DomainResult<u16> {
    let value = value.trim();
    let port = value
        .parse::<i64>()
        .map_err(|_| domain_error(code, "hysteria2 server port must be a number"))?;
    parse_port(
        port,
        code,
        "hysteria2 server port must be between 1 and 65535",
    )
}

pub(crate) fn normalize_hysteria2_packet_size(
    value: String,
    code: &'static str,
) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 obfs packet size cannot be empty")?;
    let value = value.parse::<u32>().map_err(|_| {
        domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        )
    })?;
    if value == 0 {
        return Err(domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        ));
    }
    Ok(value.to_string())
}

/// The authority of a share link's `host:port/...` part: everything before
/// the first `/` (`host:8388/?plugin=` in SIP002, `host/?sni=` in the
/// Hysteria2 URI format). Call it on the part after the last `@` only:
/// userinfo (standard base64, raw passwords, WireGuard keys) may contain
/// `/`, an authority cannot, not even inside IPv6 brackets.
pub(crate) fn strip_share_link_path(host_port: &str) -> &str {
    host_port
        .split_once('/')
        .map_or(host_port, |(authority, _)| authority)
}

/// The port the Hysteria2 URI format means when the authority has none.
pub(crate) const HYSTERIA2_DEFAULT_PORT: u16 = 443;

/// A Hysteria2 URI authority: `host`, `host:port` or a port-hopping list
/// `host:port,start-end,...`. Without a port it is 443. With a list the
/// node connects to the first entry (the start of a range) and the whole
/// list comes back normalized (`443,5000:6000`) for the server ports.
pub(crate) fn parse_hysteria2_authority(
    host_port: &str,
    code: &'static str,
) -> DomainResult<(String, u16, Option<String>)> {
    let port_text = match host_port.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .and_then(|(_, rest)| rest.strip_prefix(':')),
        None => host_port.rsplit_once(':').map(|(_, port)| port),
    };
    let Some(port_text) = port_text else {
        // `parse_host_port_for` still rejects an empty host or an
        // unclosed `[`.
        let (host, port) = parse_host_port_for(
            &format!("{host_port}:{HYSTERIA2_DEFAULT_PORT}"),
            code,
            "hysteria2",
        )?;
        return Ok((host, port, None));
    };
    if !port_text.contains([',', '-']) {
        let (host, port) = parse_host_port_for(host_port, code, "hysteria2")?;
        return Ok((host, port, None));
    }
    let ranges = normalize_hysteria2_server_port_ranges(vec![port_text.to_string()], code)?;
    let port = hysteria2_server_port_range_start(&ranges[0], code)?;
    let host_part = &host_port[..host_port.len() - port_text.len() - 1];
    let (host, port) = parse_host_port_for(&format!("{host_part}:{port}"), code, "hysteria2")?;
    Ok((host, port, Some(ranges.join(","))))
}

pub(crate) fn parse_host_port_for(
    value: &str,
    error_code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            domain_error(
                error_code,
                format!("IPv6 {protocol_name} endpoint must close with ]"),
            )
        })?;
        let port = rest.strip_prefix(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain a port"),
            )
        })?;
        (host.to_string(), port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain host and port"),
            )
        })?;
        (host.to_string(), port)
    };
    let host = required_trimmed(
        host,
        error_code,
        format!("{protocol_name} host cannot be empty"),
    )?;
    let port = port
        .parse::<i64>()
        .map_err(|_| domain_error(error_code, format!("{protocol_name} port must be a number")))?;
    let port = parse_port(
        port,
        error_code,
        format!("{protocol_name} port must be between 1 and 65535"),
    )?;

    Ok((host, port))
}
