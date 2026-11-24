//! Options shared by the proxy-line formats: plain proxies and stream
//! (transport) options.

use super::*;

/// The settings of an HTTP or SOCKS5 proxy node, however its format spells
/// them.
#[derive(Default)]
pub(crate) struct PlainProxyFields {
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    /// An HTTPS proxy (HTTP over TLS), or SOCKS5 over TLS, which the node
    /// import reports as unsupported rather than running it in the clear.
    pub(crate) tls: bool,
    /// The TLS server name; the server address when not set.
    pub(crate) server_name: Option<String>,
    pub(crate) insecure: bool,
    pub(crate) certificate_sha256: Option<String>,
    public_key_sha256: Option<String>,
    /// An option the node needs that no node field carries (one of the
    /// `NODE_UNSUPPORTED_OPTION_*` codes).
    pub(crate) unsupported: Option<&'static str>,
}

/// The node metadata of an HTTP or SOCKS5 proxy: its credentials
/// ([`NODE_METADATA_PROXY_USERNAME`], [`NODE_METADATA_PROXY_PASSWORD`]) and,
/// over TLS, the TLS entries every other protocol uses.
pub(crate) fn plain_proxy_metadata(fields: PlainProxyFields, host: &str) -> Metadata {
    let mut metadata = Vec::new();
    for (key, value) in [
        (NODE_METADATA_PROXY_USERNAME, fields.username),
        (NODE_METADATA_PROXY_PASSWORD, fields.password),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            metadata.push(MetadataEntry {
                key: key.to_string(),
                value,
            });
        }
    }
    if fields.tls {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ENABLED.to_string(),
            value: "true".to_string(),
        });
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: fields
                .server_name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| host.to_string()),
        });
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: fields.insecure.to_string(),
        });
    }
    metadata.extend(proxy_line_pin_metadata(
        fields.certificate_sha256,
        fields.public_key_sha256,
    ));
    if let Some(option) = fields.unsupported {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_UNSUPPORTED_OPTION.to_string(),
            value: option.to_string(),
        });
    }
    metadata
}

/// The protocol, reader tag and TLS of a Surge, Loon or Quantumult X proxy
/// type that is an HTTP or SOCKS5 proxy (as [`normalized_token`] spells
/// it): `http`, `https`, `socks5`, `socks` and Surge's `socks5-tls`.
pub(crate) fn plain_proxy_kind(token: &str) -> Option<(Protocol, &'static str, bool)> {
    match token {
        "http" => Some((Protocol::Http, "http", false)),
        "https" => Some((Protocol::Http, "http", true)),
        "socks5" | "socks" => Some((Protocol::Socks, "socks", false)),
        "socks5_tls" => Some((Protocol::Socks, "socks", true)),
        _ => None,
    }
}

/// The protocol, reader tag and metadata of a Surge or Loon HTTP or SOCKS5
/// proxy line of type `token` from the fields after its port.
pub(crate) fn proxy_line_plain_proxy(
    token: &str,
    fields: &[String],
    host: &str,
    code: &'static str,
) -> DomainResult<(Protocol, &'static str, Metadata)> {
    let (protocol, tag, tls) = plain_proxy_kind(token)
        .ok_or_else(|| domain_error(code, "proxy type is not http, https or socks5"))?;
    let fields = proxy_line_plain_proxy_fields(fields, tls, code)?;
    Ok((protocol, tag, plain_proxy_metadata(fields, host)))
}

/// The fields after the port of a Surge or Loon HTTP or SOCKS5 proxy line:
/// the user and password, positional (`user, "password"`) or as
/// `username=` and `password=`, then the options: `tls=`/`over-tls=`,
/// `sni=`/`tls-name=`, `skip-cert-verify=`, and the pins
/// `server-cert-fingerprint-sha256=` (Surge), `tls-cert-sha256=` and
/// `tls-pubkey-sha256=` (Loon). Other options (`udp-relay`, `tfo`, ...)
/// change nothing here and are ignored.
pub(crate) fn proxy_line_plain_proxy_fields(
    fields: &[String],
    tls: bool,
    code: &'static str,
) -> DomainResult<PlainProxyFields> {
    let mut proxy = PlainProxyFields {
        tls,
        ..PlainProxyFields::default()
    };
    let mut positional = Vec::new();
    let mut options = BTreeMap::new();
    for field in fields.iter().map(|field| field.trim()) {
        if options.is_empty() && positional.len() < 2 && !is_proxy_line_option(field) {
            positional.push(strip_loon_quotes(field.to_string()));
            continue;
        }
        if let Some((key, value)) = field.split_once('=') {
            options.insert(normalized_token(key), strip_loon_quotes(value.to_string()));
        }
    }
    let mut positional = positional.into_iter();
    proxy.username = positional
        .next()
        .or_else(|| options.get("username").cloned());
    proxy.password = positional
        .next()
        .or_else(|| options.get("password").cloned());
    if let Some(enabled) = proxy_line_boolean(
        options.get("tls").or_else(|| options.get("over_tls")),
        code,
        "proxy tls",
    )? {
        proxy.tls = enabled;
    }
    proxy.server_name = options
        .get("sni")
        .or_else(|| options.get("tls_name"))
        .filter(|sni| !sni.trim().eq_ignore_ascii_case("off"))
        .cloned();
    proxy.insecure = proxy_line_boolean(
        options.get("skip_cert_verify"),
        code,
        "proxy skip-cert-verify",
    )?
    .unwrap_or(false);
    proxy.certificate_sha256 = options
        .get("server_cert_fingerprint_sha256")
        .or_else(|| options.get("tls_cert_sha256"))
        .cloned();
    proxy.public_key_sha256 = options.get("tls_pubkey_sha256").cloned();
    Ok(proxy)
}

/// The TLS, REALITY and transport settings of a Clash, Surge, Loon or
/// Quantumult X proxy, spelled as the fields of the equivalent share link
/// (`security`, `sni`, `insecure`, `alpn`, `fp`, `pbk`, `sid`, `type`,
/// `host`, `path`, `servicename`, `mode`, `extra`), so
/// [`append_v2ray_share_link_metadata`] writes the same node metadata a share
/// link for that node would, and the node imports as the same outbound.
///
/// `unsupported` is an option the format names that no share-link field can
/// carry (one of the `NODE_UNSUPPORTED_OPTION_*` codes). It is written as
/// [`NODE_METADATA_UNSUPPORTED_OPTION`], so the importer reports the node as
/// unsupported instead of running it without that option.
#[derive(Default)]
pub(crate) struct ProxyStreamOptions {
    pub(crate) query: BTreeMap<String, String>,
    pub(crate) unsupported: Option<&'static str>,
}

impl ProxyStreamOptions {
    /// Sets share-link field `key` to `value` when it is not empty.
    pub(crate) fn set(&mut self, key: &str, value: Option<String>) {
        if let Some(value) = value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            self.query.insert(key.to_string(), value);
        }
    }

    /// Sets share-link field `key` when it is not set yet.
    pub(crate) fn set_default(&mut self, key: &str, value: Option<String>) {
        if !self.query.contains_key(key) {
            self.set(key, value);
        }
    }

    /// Records the first option that cannot be carried.
    pub(crate) fn unsupported(&mut self, code: &'static str) {
        self.unsupported.get_or_insert(code);
    }

    /// Sets `type` from a transport name: `ws`, `grpc`, `h2` and `xhttp`
    /// as share links spell them; an HTTP/1.1 header obfuscation or a name
    /// no reader knows makes the node unsupported.
    pub(crate) fn set_transport(&mut self, name: &str) {
        match normalized_token(name).as_str() {
            "" | "tcp" | "none" => {}
            "ws" | "websocket" => self.set("type", Some("ws".to_string())),
            "grpc" => self.set("type", Some("grpc".to_string())),
            "h2" => self.set("type", Some("h2".to_string())),
            "httpupgrade" | "http_upgrade" => self.set("type", Some("httpupgrade".to_string())),
            "xhttp" | "splithttp" => self.set("type", Some("xhttp".to_string())),
            "http" => self.unsupported(NODE_UNSUPPORTED_OPTION_HTTP_OBFS),
            _ => self.unsupported(NODE_UNSUPPORTED_OPTION_TRANSPORT),
        }
    }

    /// Writes the settings to `metadata`. `default_tls_enabled` is whether
    /// the protocol runs TLS when the source does not say (trojan).
    pub(crate) fn append_to(
        self,
        metadata: &mut Metadata,
        host: &str,
        default_tls_enabled: bool,
        code: &'static str,
        protocol_name: &'static str,
    ) -> DomainResult<()> {
        append_v2ray_share_link_metadata(
            metadata,
            &self.query,
            host,
            default_tls_enabled,
            code,
            protocol_name,
        )?;
        if let Some(option) = self.unsupported {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_UNSUPPORTED_OPTION.to_string(),
                value: option.to_string(),
            });
        }
        Ok(())
    }
}

/// A boolean option of a proxy line (`true`, `false`, `1`, `0`), as the
/// share-link `security`/`insecure` spelling.
pub(crate) fn proxy_line_boolean(
    value: Option<&String>,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<Option<bool>> {
    value
        .map(|value| parse_share_link_boolean(value, code, field_name))
        .transpose()
}

/// The `Host` header of a Surge `ws-headers` value (`Host:cdn.example|K:v`).
pub(crate) fn surge_ws_host_header(headers: &str) -> Option<String> {
    headers.split('|').find_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.trim()
            .trim_matches('"')
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"').trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// The metadata entry naming a Shadowsocks plugin, unless `name` is empty or
/// `none`.
pub(crate) fn shadowsocks_plugin_entry(name: Option<String>) -> Option<MetadataEntry> {
    let name = name?.trim().to_string();
    (!name.is_empty() && !name.eq_ignore_ascii_case("none")).then(|| MetadataEntry {
        key: NODE_METADATA_SHADOWSOCKS_PLUGIN.to_string(),
        value: name,
    })
}

/// The VMess security a Clash, Surge, Loon or Quantumult X proxy names, for
/// [`NODE_METADATA_VMESS_SECURITY`]. `none` and `zero` are left out: the
/// client picks the VMess security and servers take any, so such a node runs
/// with the default (`auto`) rather than being refused.
pub(crate) fn proxy_vmess_security(value: Option<String>) -> Option<MetadataEntry> {
    let value = value?.trim().to_ascii_lowercase();
    (!value.is_empty() && value != "none" && value != "zero").then(|| MetadataEntry {
        key: NODE_METADATA_VMESS_SECURITY.to_string(),
        value,
    })
}
