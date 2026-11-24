//! Wire-format helpers: SOCKS5 targets, HTTP heads and bodies, TLS
//! ClientHello parsing and header mutation.

use super::*;

pub(crate) fn socks5_command_header_valid(command_header: &NativeSocks5CommandHeader) -> bool {
    command_header.version == SOCKS5_VERSION
        && command_header.reserved == SOCKS5_RESERVED
        && matches!(
            command_header.address_type,
            SOCKS5_ADDRESS_TYPE_IPV4 | SOCKS5_ADDRESS_TYPE_DOMAIN_NAME | SOCKS5_ADDRESS_TYPE_IPV6
        )
}

pub(crate) fn socks5_connect_target_valid(target: &NativeSocks5ConnectTarget) -> bool {
    target.port != 0
        && match &target.address {
            NativeSocks5Address::Ipv4(_) | NativeSocks5Address::Ipv6(_) => true,
            NativeSocks5Address::DomainName(domain_name) => !domain_name.trim().is_empty(),
        }
}

pub(crate) fn socks5_target_host(target: &NativeSocks5ConnectTarget) -> String {
    match &target.address {
        NativeSocks5Address::Ipv4(address) => {
            format!(
                "{}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )
        }
        NativeSocks5Address::DomainName(domain_name) => domain_name.clone(),
        NativeSocks5Address::Ipv6(address) => Ipv6Addr::from(*address).to_string(),
    }
}

pub(crate) fn socks5_target_url_authority(target: &NativeSocks5ConnectTarget) -> String {
    let default_port = target.port == 80 || target.port == 443;
    match &target.address {
        NativeSocks5Address::Ipv6(address) => {
            let host = Ipv6Addr::from(*address);
            if default_port {
                format!("[{host}]")
            } else {
                format!("[{host}]:{}", target.port)
            }
        }
        _ if default_port => socks5_target_host(target),
        _ => format!("{}:{}", socks5_target_host(target), target.port),
    }
}

pub(crate) fn socks5_target_header_authority(target: &NativeSocks5ConnectTarget) -> String {
    match &target.address {
        NativeSocks5Address::Ipv6(address) => {
            format!("[{}]:{}", Ipv6Addr::from(*address), target.port)
        }
        _ => format!("{}:{}", socks5_target_host(target), target.port),
    }
}

pub fn native_socks5_connect_browser_capture_proof_token(
    target: &NativeSocks5ConnectTarget,
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    let proxy_url = format!("{proxy_scheme}://{proxy_host}:{proxy_port}");
    browser_capture_proof_token_from_connect_authority(
        &socks5_target_header_authority(target),
        &proxy_url,
    )
}

pub fn browser_capture_proof_token_from_connect_authority(
    connect_authority: &str,
    proxy_url: &str,
) -> String {
    browser_capture_proof_token_from_source(&format!(
        "connect:{connect_authority}|proxy:{proxy_url}"
    ))
}

pub(crate) fn browser_capture_proof_token_from_source(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("networkcore-browser-proof-{hash:016x}")
}

pub(crate) fn socks5_connect_http_mitm_url(target: &NativeSocks5ConnectTarget) -> String {
    let scheme = if target.port == 443 { "https" } else { "http" };
    format!("{scheme}://{}/", socks5_target_url_authority(target))
}

pub(crate) fn socks5_connect_http_mitm_request_id(target: &NativeSocks5ConnectTarget) -> String {
    format!(
        "native-socks5-connect:{}:{}",
        socks5_target_host(target),
        target.port
    )
}

pub(crate) fn http_mitm_outcome_requires_application(outcome: &HttpMitmOutcome) -> bool {
    outcome.action != HttpMitmAction::Continue
        || !outcome.header_mutations.is_empty()
        || outcome.body_mutation.is_some()
        || outcome.script_dispatch.is_some()
}

pub(crate) fn http_mitm_outcome_rejects(outcome: &HttpMitmOutcome) -> bool {
    matches!(&outcome.action, HttpMitmAction::Reject { .. })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedExplicitHttpProxyTarget {
    pub(crate) target_url: String,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) origin_path: String,
}

pub(crate) fn explicit_http_proxy_request_to_plain_http_message(
    request: &NativeExplicitHttpProxyRequest,
) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: request.request_id.clone(),
        url: request.target_url.clone(),
        method: Some(request.method.clone()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: request.headers.clone(),
        body: request.body.clone(),
        request_headers: Vec::new(),
        request_body: None,
    }
}

pub(crate) fn plain_http_proxy_response_to_plain_http_message(
    request: &NativeExplicitHttpProxyRequest,
    response: &NativePlainHttpProxyResponse,
) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: format!("{}:response", request.request_id),
        url: request.target_url.clone(),
        method: Some(request.method.clone()),
        phase: HttpMitmPhase::Response,
        status_code: Some(response.status_code),
        headers: response.headers.clone(),
        body: response.body.clone(),
        request_headers: request.headers.clone(),
        request_body: Some(request.body.clone()),
    }
}

pub(crate) fn passthrough_plain_http_rewrite_report(
    message: &NativePlainHttpMessage,
) -> NativePlainHttpRewriteReport {
    NativePlainHttpRewriteReport {
        request_id: message.request_id.clone(),
        url: message.url.clone(),
        event: plain_http_message_to_mitm_event(message),
        outcome: None,
        applied: false,
        terminal_action: None,
        final_status_code: message.status_code,
        redirect_location: None,
        headers: message.headers.clone(),
        body: message.body.clone(),
        script_dispatch_deferred: false,
        script_dispatch_executed: false,
        script_dispatch_failed: false,
        audits: Vec::new(),
        diagnostics: Vec::new(),
    }
}

pub(crate) fn read_http_header_bytes<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: Read,
{
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];

    while header.len() < HTTP_PROXY_MAX_HEADER_BYTES {
        match reader.read(&mut byte) {
            Ok(1) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    header.truncate(header.len().saturating_sub(4));
                    return Some(header);
                }
            }
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }

    None
}

pub(crate) fn parse_http_start_line_and_headers(
    header_text: &str,
) -> Option<(&str, Vec<MetadataEntry>)> {
    let mut lines = header_text.split("\r\n");
    let start_line = lines.next()?.trim();
    if start_line.is_empty() {
        return None;
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        if name.is_empty() || name.contains('\r') || name.contains('\n') {
            return None;
        }
        headers.push(MetadataEntry {
            key: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Some((start_line, headers))
}

pub(crate) fn http_content_length(headers: &[MetadataEntry], max_len: usize) -> Result<usize, ()> {
    let mut content_length = None;
    for header in headers
        .iter()
        .filter(|header| header.key.eq_ignore_ascii_case("Content-Length"))
    {
        if content_length.is_some() {
            return Err(());
        }
        let value = header.value.trim().parse::<usize>().map_err(|_| ())?;
        if value > max_len {
            return Err(());
        }
        content_length = Some(value);
    }

    Ok(content_length.unwrap_or(0))
}

pub(crate) fn read_http_body<R>(
    reader: &mut R,
    headers: &[MetadataEntry],
    max_len: usize,
) -> Result<Vec<u8>, ()>
where
    R: Read,
{
    let transfer_encoding = headers
        .iter()
        .filter(|header| header.key.eq_ignore_ascii_case("Transfer-Encoding"))
        .map(|header| header.value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if !transfer_encoding.is_empty() {
        if headers
            .iter()
            .any(|header| header.key.eq_ignore_ascii_case("Content-Length"))
        {
            return Err(());
        }
        let codings = transfer_encoding
            .iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .collect::<Vec<_>>();
        if codings.len() != 1
            || codings[0].is_empty()
            || !codings[0].eq_ignore_ascii_case("chunked")
        {
            return Err(());
        }
        return read_chunked_http_body(reader, max_len);
    }

    let body_len = http_content_length(headers, max_len)?;
    let mut body = vec![0_u8; body_len];
    if body_len > 0 {
        reader.read_exact(&mut body).map_err(|_| ())?;
    }
    Ok(body)
}

pub(crate) fn read_chunked_http_body<R>(reader: &mut R, max_len: usize) -> Result<Vec<u8>, ()>
where
    R: Read,
{
    let mut body = Vec::new();
    loop {
        let size_line = read_http_line(reader).ok_or(())?;
        let size_text = size_line
            .split_once(';')
            .map(|(size, _)| size)
            .unwrap_or(size_line.as_str())
            .trim();
        if size_text.is_empty() {
            return Err(());
        }
        let chunk_len = usize::from_str_radix(size_text, 16).map_err(|_| ())?;
        if chunk_len == 0 {
            loop {
                let trailer = read_http_line(reader).ok_or(())?;
                if trailer.is_empty() {
                    return Ok(body);
                }
                let (name, value) = trailer.split_once(':').ok_or(())?;
                let name = name.trim();
                if name.is_empty()
                    || name.eq_ignore_ascii_case("Content-Length")
                    || name.eq_ignore_ascii_case("Transfer-Encoding")
                    || value.contains('\r')
                    || value.contains('\n')
                {
                    return Err(());
                }
            }
        }
        if chunk_len > max_len.saturating_sub(body.len()) {
            return Err(());
        }
        let mut chunk = vec![0_u8; chunk_len];
        reader.read_exact(&mut chunk).map_err(|_| ())?;
        body.extend_from_slice(&chunk);
        let mut terminator = [0_u8; 2];
        reader.read_exact(&mut terminator).map_err(|_| ())?;
        if terminator != *b"\r\n" {
            return Err(());
        }
    }
}

pub(crate) fn read_http_line<R>(reader: &mut R) -> Option<String>
where
    R: Read,
{
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while line.len() < HTTP_PROXY_MAX_HEADER_BYTES {
        match reader.read(&mut byte) {
            Ok(1) => {
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len().saturating_sub(2));
                    return String::from_utf8(line).ok();
                }
            }
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
    None
}

pub(crate) fn parse_explicit_http_proxy_target(
    method: &str,
    target: &str,
    headers: &[MetadataEntry],
) -> Option<ParsedExplicitHttpProxyTarget> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (target_host, target_port) = parse_http_authority(target, 443)?;
        let authority = http_url_authority(&target_host, target_port, 443);
        return Some(ParsedExplicitHttpProxyTarget {
            target_url: format!("https://{authority}/"),
            target_host,
            target_port,
            origin_path: String::new(),
        });
    }

    if let Some(rest) = target.strip_prefix("http://") {
        return parse_absolute_http_proxy_target("http", rest, 80);
    }
    if let Some(rest) = target.strip_prefix("https://") {
        return parse_absolute_http_proxy_target("https", rest, 443);
    }

    if target.starts_with('/') {
        let host = headers
            .iter()
            .find(|header| header.key.eq_ignore_ascii_case("Host"))?
            .value
            .trim();
        let (target_host, target_port) = parse_http_authority(host, 80)?;
        let authority = http_url_authority(&target_host, target_port, 80);
        return Some(ParsedExplicitHttpProxyTarget {
            target_url: format!("http://{authority}{target}"),
            target_host,
            target_port,
            origin_path: target.to_string(),
        });
    }

    None
}

pub(crate) fn parse_absolute_http_proxy_target(
    scheme: &str,
    rest: &str,
    default_port: u16,
) -> Option<ParsedExplicitHttpProxyTarget> {
    let path_start = rest
        .find('/')
        .or_else(|| rest.find('?'))
        .unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let raw_path = &rest[path_start..];
    let origin_path = if raw_path.is_empty() {
        "/".to_string()
    } else if raw_path.starts_with('?') {
        format!("/{raw_path}")
    } else {
        raw_path.to_string()
    };
    let (target_host, target_port) = parse_http_authority(authority, default_port)?;
    let authority = http_url_authority(&target_host, target_port, default_port);

    Some(ParsedExplicitHttpProxyTarget {
        target_url: format!("{scheme}://{authority}{origin_path}"),
        target_host,
        target_port,
        origin_path,
    })
}

pub(crate) fn parse_http_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return None;
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            let port = suffix.strip_prefix(':')?;
            parse_http_port(port)?
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, parse_http_port(port)?),
            Some(_) => return None,
            None => (authority, default_port),
        }
    };

    if host.trim().is_empty() || port == 0 {
        return None;
    }

    Some((host.to_string(), port))
}

pub(crate) fn parse_http_port(port: &str) -> Option<u16> {
    let port = port.trim().parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

pub(crate) fn http_url_authority(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn http_host_header_authority(host: &str, port: u16) -> String {
    http_url_authority(host, port, 80)
}

pub(crate) fn explicit_http_proxy_request_to_socks5_target(
    request: &NativeExplicitHttpProxyRequest,
) -> NativeSocks5ConnectTarget {
    let address = match request.target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => NativeSocks5Address::Ipv4(address.octets()),
        Ok(IpAddr::V6(address)) => NativeSocks5Address::Ipv6(address.octets()),
        Err(_) => NativeSocks5Address::DomainName(request.target_host.clone()),
    };

    NativeSocks5ConnectTarget {
        address,
        port: request.target_port,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsClientHelloMetadata {
    pub(crate) sni_hostname: Option<String>,
    pub(crate) alpn_protocols: Vec<Vec<u8>>,
    pub(crate) tls_record_version: String,
    pub(crate) tls_handshake_version: String,
}

pub(crate) fn parse_tls_client_hello_metadata(bytes: &[u8]) -> Option<TlsClientHelloMetadata> {
    if *bytes.first()? != 0x16 {
        return None;
    }

    let tls_record_version = format_tls_version(*bytes.get(1)?, *bytes.get(2)?);
    let record_len = u16::from_be_bytes([*bytes.get(3)?, *bytes.get(4)?]) as usize;
    let record_end = 5_usize.checked_add(record_len)?;
    if bytes.len() < record_end {
        return None;
    }

    let handshake = &bytes[5..record_end];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    let handshake_end = 4_usize.checked_add(handshake_len)?;
    if handshake.len() < handshake_end {
        return None;
    }

    let body = &handshake[4..handshake_end];
    if body.len() < 34 {
        return None;
    }

    let tls_handshake_version = format_tls_version(body[0], body[1]);
    let mut cursor = 34_usize;

    let session_id_len = *body.get(cursor)? as usize;
    cursor = cursor.checked_add(1)?.checked_add(session_id_len)?;
    if cursor > body.len() || cursor.checked_add(2)? > body.len() {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor = cursor.checked_add(2)?.checked_add(cipher_suites_len)?;
    if cursor >= body.len() {
        return None;
    }

    let compression_methods_len = body[cursor] as usize;
    cursor = cursor
        .checked_add(1)?
        .checked_add(compression_methods_len)?;
    if cursor > body.len() {
        return None;
    }

    let sni_hostname = parse_tls_client_hello_sni_extension(&body[cursor..]);
    let alpn_protocols = parse_tls_client_hello_alpn_extension(&body[cursor..]);

    Some(TlsClientHelloMetadata {
        sni_hostname,
        alpn_protocols,
        tls_record_version,
        tls_handshake_version,
    })
}

pub(crate) fn parse_tls_client_hello_sni_extension(bytes: &[u8]) -> Option<String> {
    parse_tls_server_name_extension(find_tls_client_hello_extension(bytes, 0x0000)?)
}

pub(crate) fn parse_tls_client_hello_alpn_extension(bytes: &[u8]) -> Vec<Vec<u8>> {
    find_tls_client_hello_extension(bytes, 0x0010)
        .and_then(parse_tls_alpn_protocol_name_list)
        .unwrap_or_default()
}

pub(crate) fn find_tls_client_hello_extension(bytes: &[u8], wanted_type: u16) -> Option<&[u8]> {
    if bytes.len() < 2 {
        return None;
    }

    let extensions_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let extensions_end = 2_usize.checked_add(extensions_len)?;
    if bytes.len() < extensions_end {
        return None;
    }

    let extensions = &bytes[2..extensions_end];
    let mut cursor = 0_usize;
    while cursor.checked_add(4)? <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_len =
            u16::from_be_bytes([extensions[cursor + 2], extensions[cursor + 3]]) as usize;
        cursor = cursor.checked_add(4)?;
        let extension_end = cursor.checked_add(extension_len)?;
        if extension_end > extensions.len() {
            return None;
        }

        if extension_type == wanted_type {
            return Some(&extensions[cursor..extension_end]);
        }

        cursor = extension_end;
    }

    None
}

pub(crate) fn parse_tls_alpn_protocol_name_list(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let list_end = 2_usize.checked_add(list_len)?;
    if bytes.len() < list_end {
        return None;
    }

    let mut protocols = Vec::new();
    let mut cursor = 2_usize;
    while cursor < list_end {
        let name_len = bytes[cursor] as usize;
        cursor = cursor.checked_add(1)?;
        let name_end = cursor.checked_add(name_len)?;
        if name_len == 0 || name_end > list_end {
            return None;
        }
        protocols.push(bytes[cursor..name_end].to_vec());
        cursor = name_end;
    }

    Some(protocols)
}

/// Returns the ALPN protocol names a complete TLS ClientHello record offers,
/// in client preference order. Malformed or truncated input yields an empty
/// list, which the controlled TLS path treats as an HTTP/1.1-only client.
pub fn observe_tls_client_hello_alpn_protocols(bytes: &[u8]) -> Vec<String> {
    parse_tls_client_hello_metadata(bytes)
        .map(|metadata| {
            metadata
                .alpn_protocols
                .iter()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_tls_server_name_extension(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let names_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let names_end = 2_usize.checked_add(names_len)?;
    if bytes.len() < names_end {
        return None;
    }

    let mut cursor = 2_usize;
    while cursor.checked_add(3)? <= names_end {
        let name_type = bytes[cursor];
        let name_len = u16::from_be_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
        cursor = cursor.checked_add(3)?;
        let name_end = cursor.checked_add(name_len)?;
        if name_end > names_end {
            return None;
        }

        if name_type == 0x00 {
            let hostname = std::str::from_utf8(&bytes[cursor..name_end]).ok()?;
            let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
            if tls_sni_hostname_valid(&hostname) {
                return Some(hostname);
            }
            return None;
        }

        cursor = name_end;
    }

    None
}

pub(crate) fn tls_sni_hostname_valid(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && !hostname.starts_with('.')
        && !hostname.ends_with('.')
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

pub(crate) fn tls_sni_matches_connect_authority(
    connect_host: &str,
    sni_hostname: Option<&str>,
) -> bool {
    let connect_host = connect_host.trim_end_matches('.').to_ascii_lowercase();
    let Some(sni_hostname) = sni_hostname else {
        return false;
    };
    !connect_host.is_empty()
        && connect_host == sni_hostname.trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn format_tls_version(major: u8, minor: u8) -> String {
    match (major, minor) {
        (0x03, 0x01) => "TLS 1.0".to_string(),
        (0x03, 0x02) => "TLS 1.1".to_string(),
        (0x03, 0x03) => "TLS 1.2".to_string(),
        (0x03, 0x04) => "TLS 1.3".to_string(),
        _ => format!("0x{major:02x}{minor:02x}"),
    }
}

pub(crate) fn write_http_headers_to_bytes(bytes: &mut Vec<u8>, headers: &[MetadataEntry]) {
    for header in headers.iter().filter(|header| http_header_safe(header)) {
        bytes.extend_from_slice(header.key.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(header.value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
}

pub(crate) fn http_header_safe(header: &MetadataEntry) -> bool {
    !header.key.trim().is_empty()
        && !header.key.contains('\r')
        && !header.key.contains('\n')
        && !header.value.contains('\r')
        && !header.value.contains('\n')
}

pub(crate) fn normalized_http_version(version: &str) -> &str {
    if version.starts_with("HTTP/") {
        version
    } else {
        "HTTP/1.1"
    }
}

pub(crate) fn http_message_requests_close(version: &str, headers: &[MetadataEntry]) -> bool {
    if headers.iter().any(|header| {
        header.key.eq_ignore_ascii_case("Connection")
            && header
                .value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
    }) {
        return true;
    }

    version.eq_ignore_ascii_case("HTTP/1.0")
        && !headers.iter().any(|header| {
            header.key.eq_ignore_ascii_case("Connection")
                && header
                    .value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("keep-alive"))
        })
}

pub(crate) fn http_reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        501 => "Not Implemented",
        _ => "NetworkCore",
    }
}

pub(crate) fn plain_http_status_response(version: &str, status_code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{} {} {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        normalized_http_version(version),
        status_code,
        http_reason_phrase(status_code),
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub(crate) fn explicit_http_proxy_request_read_failed() -> NativeExplicitHttpProxyRequestReadReport
{
    NativeExplicitHttpProxyRequestReadReport {
        request: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_FAILED_CODE,
            "native explicit HTTP proxy request could not be read",
        )],
    }
}

pub(crate) fn explicit_http_proxy_request_invalid(
    message: &'static str,
) -> NativeExplicitHttpProxyRequestReadReport {
    NativeExplicitHttpProxyRequestReadReport {
        request: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_INVALID_CODE,
            message,
        )],
    }
}

pub(crate) fn explicit_http_proxy_request_http_version_unsupported(
) -> NativeExplicitHttpProxyRequestReadReport {
    NativeExplicitHttpProxyRequestReadReport {
        request: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_HTTP_VERSION_UNSUPPORTED_CODE,
            "native explicit HTTP proxy supports HTTP/1.0 and HTTP/1.1 only",
        )],
    }
}

pub(crate) fn plain_http_proxy_response_read_failed() -> NativePlainHttpProxyResponseReadReport {
    NativePlainHttpProxyResponseReadReport {
        response: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
            "native plain HTTP proxy upstream response could not be read",
        )],
    }
}

pub(crate) fn plain_http_proxy_response_http_version_unsupported(
) -> NativePlainHttpProxyResponseReadReport {
    NativePlainHttpProxyResponseReadReport {
        response: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_HTTP_VERSION_UNSUPPORTED_CODE,
            "native explicit HTTP proxy upstream response must use HTTP/1.0 or HTTP/1.1",
        )],
    }
}

pub(crate) fn plain_http_message_to_mitm_event(message: &NativePlainHttpMessage) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: message.request_id.clone(),
        url: message.url.clone(),
        method: message.method.clone(),
        phase: message.phase,
        status_code: message.status_code,
        headers: message.headers.clone(),
        body: message.body.clone(),
    }
}

pub(crate) fn apply_plain_http_header_mutations(
    headers: &mut Vec<MetadataEntry>,
    mutations: &[HttpHeaderMutation],
) -> usize {
    let mut applied = 0;

    for mutation in mutations {
        if apply_plain_http_header_mutation(headers, mutation) {
            applied += 1;
        }
    }

    applied
}

pub(crate) fn apply_plain_http_header_mutation(
    headers: &mut Vec<MetadataEntry>,
    mutation: &HttpHeaderMutation,
) -> bool {
    match mutation.operation {
        HttpHeaderMutationOperation::Add => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            headers.push(MetadataEntry {
                key: mutation.name.clone(),
                value: value.clone(),
            });
            true
        }
        HttpHeaderMutationOperation::Replace => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            let mut replaced = false;
            for header in headers
                .iter_mut()
                .filter(|header| header.key.eq_ignore_ascii_case(&mutation.name))
            {
                header.value = value.clone();
                replaced = true;
            }
            replaced
        }
        HttpHeaderMutationOperation::Delete => {
            let original_len = headers.len();
            headers.retain(|header| !header.key.eq_ignore_ascii_case(&mutation.name));
            headers.len() != original_len
        }
        HttpHeaderMutationOperation::Set => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            set_plain_http_header(headers, &mutation.name, value);
            true
        }
    }
}

pub(crate) fn set_plain_http_header(headers: &mut Vec<MetadataEntry>, name: &str, value: &str) {
    headers.retain(|header| !header.key.eq_ignore_ascii_case(name));
    headers.push(MetadataEntry {
        key: name.to_string(),
        value: value.to_string(),
    });
}

pub(crate) fn remove_plain_http_header(headers: &mut Vec<MetadataEntry>, name: &str) {
    headers.retain(|header| !header.key.eq_ignore_ascii_case(name));
}

pub(crate) fn plain_http_header_value(headers: &[MetadataEntry], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn https_response_body_content_type_guard_ready(headers: &[MetadataEntry]) -> bool {
    plain_http_header_value(headers, "Content-Type")
        .as_deref()
        .map(https_response_body_content_type_supported)
        .unwrap_or(false)
}

pub(crate) fn https_response_body_content_type_supported(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    media_type.starts_with("text/")
        || media_type == "application/json"
        || media_type == "application/javascript"
        || media_type == "application/x-javascript"
        || media_type == "application/xml"
        || media_type == "application/xhtml+xml"
        || media_type == "application/x-www-form-urlencoded"
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

pub(crate) fn https_response_body_buffering_guard_ready(
    input_body: &[u8],
    output_body: Option<&[u8]>,
) -> bool {
    input_body.len() <= HTTP_PROXY_MAX_BODY_BYTES
        && output_body
            .map(|body| body.len() <= HTTP_PROXY_MAX_BODY_BYTES)
            .unwrap_or(true)
}

pub(crate) fn socks5_outbound_connect_response_valid(
    response: &NativeSocks5OutboundConnectResponse,
) -> bool {
    response.version == SOCKS5_VERSION
        && response.reply == SOCKS5_REPLY_SUCCEEDED
        && response.reserved == SOCKS5_RESERVED
        && match (response.address_type, &response.bound_address) {
            (SOCKS5_ADDRESS_TYPE_IPV4, NativeSocks5Address::Ipv4(_)) => true,
            (SOCKS5_ADDRESS_TYPE_IPV6, NativeSocks5Address::Ipv6(_)) => true,
            (SOCKS5_ADDRESS_TYPE_DOMAIN_NAME, NativeSocks5Address::DomainName(domain_name)) => {
                !domain_name.trim().is_empty() && domain_name.len() <= u8::MAX as usize
            }
            _ => false,
        }
}

pub(crate) fn relay_socks5_outbound_connect_data_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<u64>
where
    R: Read,
    W: Write,
{
    let bytes = std::io::copy(reader, writer)?;
    writer.flush()?;

    Ok(bytes)
}

pub(crate) fn socks5_outbound_connect_client_success_response_frame(
    response: &NativeSocks5OutboundConnectResponse,
) -> Option<Vec<u8>> {
    if !socks5_outbound_connect_response_valid(response) {
        return None;
    }

    let mut frame = vec![SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, SOCKS5_RESERVED];
    match &response.bound_address {
        NativeSocks5Address::Ipv4(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV4);
            frame.extend_from_slice(address);
        }
        NativeSocks5Address::DomainName(domain_name) => {
            let domain_name = domain_name.as_bytes();
            frame.push(SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
            frame.push(domain_name.len() as u8);
            frame.extend_from_slice(domain_name);
        }
        NativeSocks5Address::Ipv6(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV6);
            frame.extend_from_slice(address);
        }
    }
    frame.extend_from_slice(&response.bound_port.to_be_bytes());

    Some(frame)
}

pub(crate) fn socks5_outbound_connect_request_frame_bytes(
    target: &NativeSocks5ConnectTarget,
) -> Option<Vec<u8>> {
    if !socks5_connect_target_valid(target) {
        return None;
    }

    let mut frame = vec![SOCKS5_VERSION, SOCKS5_COMMAND_CONNECT, SOCKS5_RESERVED];
    match &target.address {
        NativeSocks5Address::Ipv4(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV4);
            frame.extend_from_slice(address);
        }
        NativeSocks5Address::DomainName(domain_name) => {
            let domain_name = domain_name.as_bytes();
            if domain_name.len() > u8::MAX as usize {
                return None;
            }
            frame.push(SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
            frame.push(domain_name.len() as u8);
            frame.extend_from_slice(domain_name);
        }
        NativeSocks5Address::Ipv6(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV6);
            frame.extend_from_slice(address);
        }
    }
    frame.extend_from_slice(&target.port.to_be_bytes());

    Some(frame)
}

pub(crate) fn endpoint_socket_addr(endpoint: &Endpoint) -> Option<SocketAddr> {
    if endpoint.port == 0 {
        return None;
    }

    endpoint
        .host
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|host| SocketAddr::new(host, endpoint.port))
}

pub(crate) fn socks5_connect_target_read_failed(
    message: &'static str,
) -> NativeSocks5ConnectTargetReadReport {
    NativeSocks5ConnectTargetReadReport {
        target: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE,
            message,
        )],
    }
}

pub(crate) fn socks5_outbound_connect_response_read_failed(
    message: &'static str,
) -> NativeSocks5OutboundConnectResponseReadReport {
    NativeSocks5OutboundConnectResponseReadReport {
        response: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE,
            message,
        )],
    }
}

pub(crate) fn relay_socks5_outbound_connect_tcp_streams(
    client_stream: &TcpStream,
    outbound_stream: &TcpStream,
) -> NativeSocks5OutboundConnectDataRelayReport {
    let Ok(mut client_reader) = client_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut outbound_writer) = outbound_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut outbound_reader) = outbound_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut client_writer) = client_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };

    let _ = client_reader.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let _ = outbound_reader.set_read_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
    )));
    let _ = outbound_writer.set_write_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
    )));

    relay_socks5_outbound_connect_data(
        &mut client_reader,
        &mut outbound_writer,
        &mut outbound_reader,
        &mut client_writer,
    )
}

pub(crate) fn socks5_outbound_connect_data_relay_failed(
) -> NativeSocks5OutboundConnectDataRelayReport {
    NativeSocks5OutboundConnectDataRelayReport {
        client_to_outbound_bytes: 0,
        outbound_to_client_bytes: 0,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
            "native SOCKS5 outbound CONNECT data relay stream handles could not be prepared",
        )],
    }
}

pub(crate) fn diagnostics_contain_code(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

pub(crate) fn diagnostics_contain_client_success_written(diagnostics: &[Diagnostic]) -> bool {
    diagnostics_contain_code(
        diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
    )
}

pub(crate) fn diagnostics_contain_data_relay_completed(diagnostics: &[Diagnostic]) -> bool {
    diagnostics_contain_code(
        diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    )
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}
