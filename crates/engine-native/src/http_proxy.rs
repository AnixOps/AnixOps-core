//! The plain HTTP proxy: MITM of plain HTTP, reading and writing proxy
//! requests and responses.

use super::*;

pub fn plan_and_apply_plain_http_mitm(
    message: &NativePlainHttpMessage,
    plugin_instance: &PluginInstance,
    plugin_service: &dyn MitmPluginService,
) -> NativePlainHttpRewriteReport {
    let event = plain_http_message_to_mitm_event(message);
    let mut diagnostics = vec![engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE,
        "native plain HTTP message was mapped to a rich HTTP MITM event",
        SOURCE_ENGINE_NATIVE_MITM,
    )];

    match plugin_service.handle_http_mitm_event(plugin_instance, &event) {
        Ok(outcome) => {
            let audits = outcome.audits.clone();
            diagnostics.extend(outcome.diagnostics.clone());
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE,
                "native plain HTTP MITM plugin plan was produced",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            let application = apply_http_mitm_outcome_to_plain_http_message(message, &outcome);
            diagnostics.extend(application.diagnostics.clone());

            NativePlainHttpRewriteReport {
                request_id: message.request_id.clone(),
                url: message.url.clone(),
                event,
                outcome: Some(outcome),
                applied: application.applied,
                terminal_action: application.terminal_action,
                final_status_code: application.final_status_code,
                redirect_location: application.redirect_location,
                headers: application.headers,
                body: application.body,
                script_dispatch_deferred: application.script_dispatch_deferred,
                script_dispatch_executed: false,
                script_dispatch_failed: false,
                audits,
                diagnostics,
            }
        }
        Err(_error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_FAILED_CODE,
                "native plain HTTP MITM plugin plan failed",
                SOURCE_ENGINE_NATIVE_MITM,
            ));

            NativePlainHttpRewriteReport {
                request_id: message.request_id.clone(),
                url: message.url.clone(),
                event,
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
                diagnostics,
            }
        }
    }
}

/// Terminal action name for [`HttpMitmAction::Respond`].
pub const LOCAL_RESPONSE_TERMINAL_ACTION: &str = "local-response";

/// The rule's headers with a `Content-Length` that matches the local body.
pub(crate) fn local_response_headers(
    headers: &[MetadataEntry],
    body_len: usize,
) -> Vec<MetadataEntry> {
    let mut headers = headers.to_vec();
    set_plain_http_header(&mut headers, "Content-Length", &body_len.to_string());
    headers
}

pub fn apply_http_mitm_outcome_to_plain_http_message(
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativePlainHttpRewriteApplication {
    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;
    let mut script_dispatch_deferred = false;
    let mut diagnostics = Vec::new();

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            redirect_location = None;
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
                "native plain HTTP data plane applied a reject terminal action",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
        HttpMitmAction::Redirect {
            status_code,
            location,
        } => {
            applied = true;
            terminal_action = Some("redirect".to_string());
            final_status_code = Some(*status_code);
            redirect_location = Some(location.clone());
            set_plain_http_header(&mut headers, "Location", location);
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
                "native plain HTTP data plane applied a redirect terminal action",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
        HttpMitmAction::Respond {
            status_code,
            headers: response_headers,
            body: response_body,
        } => {
            applied = true;
            terminal_action = Some(LOCAL_RESPONSE_TERMINAL_ACTION.to_string());
            final_status_code = Some(*status_code);
            redirect_location = None;
            headers = local_response_headers(response_headers, response_body.len());
            body = response_body.clone();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
                "native plain HTTP data plane answered the request with a local response",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }

    if terminal_action.is_none() {
        let header_mutations_applied =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        if header_mutations_applied > 0 {
            applied = true;
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
                format!(
                    "native plain HTTP data plane applied {header_mutations_applied} header mutation(s)"
                ),
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }

        if let Some(body_mutation) = &outcome.body_mutation {
            applied = true;
            body = body_mutation.body.clone();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
                "native plain HTTP data plane applied a body mutation",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }

    if outcome.script_dispatch.is_some() {
        script_dispatch_deferred = true;
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE,
            "native plain HTTP data plane recorded script dispatch but script execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    if !applied && !script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_REWRITE_NOOP_CODE,
            "native plain HTTP data plane found no rewrite mutation to apply",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativePlainHttpRewriteApplication {
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        headers,
        body,
        script_dispatch_deferred,
        diagnostics,
    }
}

pub fn write_http_mitm_rejected_socks5_connect_failure_response<W>(
    writer: &mut W,
) -> NativeSocks5ConnectFailureResponseWriteReport
where
    W: Write,
{
    let response = SOCKS5_CONNECT_FAILURE_RESPONSE;
    let diagnostic = if writer.write_all(&response).is_ok() {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 CONNECT failure response was written for MITM plugin rejection",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 CONNECT failure response could not be written for MITM plugin rejection",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativeSocks5ConnectFailureResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_explicit_http_proxy_request<R>(
    reader: &mut R,
) -> NativeExplicitHttpProxyRequestReadReport
where
    R: Read,
{
    let header_bytes = match read_http_header_bytes(reader) {
        Some(header_bytes) => header_bytes,
        None => return explicit_http_proxy_request_read_failed(),
    };
    let header_text = match String::from_utf8(header_bytes) {
        Ok(header_text) => header_text,
        Err(_) => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request header must be valid UTF-8",
            );
        }
    };
    let (request_line, headers) = match parse_http_start_line_and_headers(&header_text) {
        Some(parsed) => parsed,
        None => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request header is invalid",
            );
        }
    };
    let mut request_parts = request_line.split_whitespace();
    let Some(method) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request method is missing",
        );
    };
    let Some(target) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request target is missing",
        );
    };
    let Some(version) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request version is missing",
        );
    };
    if request_parts.next().is_some() || !version.starts_with("HTTP/") {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request line is invalid",
        );
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return explicit_http_proxy_request_http_version_unsupported();
    }
    let body = match read_http_body(reader, &headers, HTTP_PROXY_MAX_BODY_BYTES) {
        Ok(body) => body,
        Err(()) => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request body framing is unsupported or exceeds the limit",
            );
        }
    };
    let Some(parsed_target) = parse_explicit_http_proxy_target(method, target, &headers) else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request target is unsupported",
        );
    };

    let request = NativeExplicitHttpProxyRequest {
        request_id: format!("native-http-proxy:{}:{}", method, parsed_target.target_url),
        method: method.to_string(),
        target_url: parsed_target.target_url,
        target_host: parsed_target.target_host,
        target_port: parsed_target.target_port,
        origin_path: parsed_target.origin_path,
        version: version.to_string(),
        headers,
        body,
    };

    NativeExplicitHttpProxyRequestReadReport {
        request: Some(request),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
            "native explicit HTTP proxy request was read",
        )],
    }
}

pub fn read_https_connect_http_request<R>(
    reader: &mut R,
    connect_request: &NativeExplicitHttpProxyRequest,
) -> NativeExplicitHttpProxyRequestReadReport
where
    R: Read,
{
    let mut read_report = read_explicit_http_proxy_request(reader);
    let Some(request) = read_report.request.as_mut() else {
        return read_report;
    };

    let connect_host = connect_request
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let request_host = request
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if request.method.eq_ignore_ascii_case("CONNECT")
        || connect_host.is_empty()
        || request_host != connect_host
    {
        return explicit_http_proxy_request_invalid(
            "native controlled TLS CONNECT request authority must match the decrypted HTTP Host authority",
        );
    }

    let authority = http_url_authority(
        &connect_request.target_host,
        connect_request.target_port,
        443,
    );
    request.target_host = connect_request.target_host.clone();
    request.target_port = connect_request.target_port;
    request.target_url = format!("https://{authority}{}", request.origin_path);
    request.request_id = format!(
        "native-https-connect:{}:{}",
        request.method, request.target_url
    );
    read_report.diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
        "native explicit HTTP proxy CONNECT decrypted a bounded HTTP/1.1 request bound to the CONNECT authority",
        SOURCE_ENGINE_NATIVE_MITM,
    ));
    read_report
}

/// Reads one upstream response as the answer to a `GET`. See
/// [`read_plain_http_proxy_response_for_request`].
pub fn read_plain_http_proxy_response<R>(reader: &mut R) -> NativePlainHttpProxyResponseReadReport
where
    R: Read,
{
    read_plain_http_proxy_response_for_request(reader, "GET")
}

/// Reads the final upstream response to a `request_method` request, framed
/// as RFC 9112 section 6.3 says: no body for `HEAD` and for 1xx, 204 and
/// 304 answers; then `Transfer-Encoding: chunked`, then `Content-Length`;
/// with neither, the body runs to the end of the connection, up to the
/// body limit (a longer one fails rather than being cut short). Interim
/// 1xx answers (other than 101) are skipped; see
/// [`read_plain_http_proxy_response_with_interim`] to forward them.
pub fn read_plain_http_proxy_response_for_request<R>(
    reader: &mut R,
    request_method: &str,
) -> NativePlainHttpProxyResponseReadReport
where
    R: Read,
{
    read_plain_http_proxy_response_with_interim(reader, request_method).0
}

/// Interim (1xx) answers an upstream may send before its final one.
pub(crate) const HTTP_PROXY_MAX_INTERIM_RESPONSES: usize = 8;

/// [`read_plain_http_proxy_response_for_request`], also returning the raw
/// heads of the interim 1xx answers before the final one (`100 Continue`,
/// `103 Early Hints`), to be forwarded to the client first.
pub(crate) fn read_plain_http_proxy_response_with_interim<R>(
    reader: &mut R,
    request_method: &str,
) -> (NativePlainHttpProxyResponseReadReport, Vec<u8>)
where
    R: Read,
{
    let mut interim = Vec::new();
    for _ in 0..=HTTP_PROXY_MAX_INTERIM_RESPONSES {
        let head = match read_plain_http_proxy_response_head(reader) {
            Ok(head) => head,
            Err(report) => return (*report, interim),
        };
        if (100..200).contains(&head.status_code) {
            // A protocol switch cannot be relayed as HTTP/1.1 messages.
            if head.status_code == 101 {
                return (plain_http_proxy_response_read_failed(), interim);
            }
            interim.extend_from_slice(&head.raw);
            interim.extend_from_slice(b"\r\n\r\n");
            continue;
        }
        let body = if response_has_no_body(request_method, head.status_code) {
            Ok(Vec::new())
        } else if http_message_has_length(&head.headers) {
            read_http_body(reader, &head.headers, HTTP_PROXY_MAX_BODY_BYTES)
        } else {
            read_http_body_to_end(reader, HTTP_PROXY_MAX_BODY_BYTES)
        };
        let Ok(body) = body else {
            return (plain_http_proxy_response_read_failed(), interim);
        };
        return (
            NativePlainHttpProxyResponseReadReport {
                response: Some(NativePlainHttpProxyResponse {
                    version: head.version,
                    status_code: head.status_code,
                    reason_phrase: head.reason_phrase,
                    headers: head.headers,
                    body,
                }),
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE,
                    "native plain HTTP proxy upstream response was read",
                )],
            },
            interim,
        );
    }
    (plain_http_proxy_response_read_failed(), interim)
}

/// The head of one upstream response, with its raw bytes (without the
/// blank line) for relaying an interim answer as it came.
pub(crate) struct NativePlainHttpProxyResponseHead {
    pub(crate) raw: Vec<u8>,
    pub(crate) version: String,
    pub(crate) status_code: u16,
    pub(crate) reason_phrase: String,
    pub(crate) headers: Vec<MetadataEntry>,
}

pub(crate) fn read_plain_http_proxy_response_head<R>(
    reader: &mut R,
) -> Result<NativePlainHttpProxyResponseHead, Box<NativePlainHttpProxyResponseReadReport>>
where
    R: Read,
{
    let Some(raw) = read_http_header_bytes(reader) else {
        return Err(Box::new(NativePlainHttpProxyResponseReadReport {
            response: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                "native plain HTTP proxy upstream response could not be read",
            )],
        }));
    };
    let Ok(header_text) = std::str::from_utf8(&raw) else {
        return Err(Box::new(NativePlainHttpProxyResponseReadReport {
            response: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                "native plain HTTP proxy upstream response header must be valid UTF-8",
            )],
        }));
    };
    let Some((status_line, headers)) = parse_http_start_line_and_headers(header_text) else {
        return Err(Box::new(NativePlainHttpProxyResponseReadReport {
            response: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                "native plain HTTP proxy upstream response header is invalid",
            )],
        }));
    };
    let mut status_parts = status_line.splitn(3, ' ');
    let Some(version) = status_parts.next() else {
        return Err(Box::new(plain_http_proxy_response_read_failed()));
    };
    let Some(status_code) = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return Err(Box::new(plain_http_proxy_response_read_failed()));
    };
    if !version.starts_with("HTTP/") {
        return Err(Box::new(plain_http_proxy_response_read_failed()));
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Box::new(
            plain_http_proxy_response_http_version_unsupported(),
        ));
    }
    let version = version.to_string();
    let reason_phrase = status_parts.next().unwrap_or("").to_string();
    Ok(NativePlainHttpProxyResponseHead {
        raw,
        version,
        status_code,
        reason_phrase,
        headers,
    })
}

/// A response to `request_method` with `status_code` that never has a
/// body (RFC 9112 section 6.3, items 1 and 2).
pub(crate) fn response_has_no_body(request_method: &str, status_code: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
}

pub(crate) fn http_message_has_length(headers: &[MetadataEntry]) -> bool {
    headers.iter().any(|header| {
        header.key.eq_ignore_ascii_case("Content-Length")
            || header.key.eq_ignore_ascii_case("Transfer-Encoding")
    })
}

/// Whether `response`, the answer to `request_method`, ends only when the
/// upstream closes: it has a body and no length of its own. Such a
/// connection cannot carry another exchange.
pub(crate) fn response_is_close_delimited(
    request_method: &str,
    response: &NativePlainHttpProxyResponse,
) -> bool {
    !response_has_no_body(request_method, response.status_code)
        && !http_message_has_length(&response.headers)
}

/// A body that runs to the end of the connection. A clean end (`Ok(0)`)
/// ends it; a timeout or error fails, never cutting the body short, and so
/// does a body over `max_len`.
pub(crate) fn read_http_body_to_end<R>(reader: &mut R, max_len: usize) -> Result<Vec<u8>, ()>
where
    R: Read,
{
    let mut body = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(body),
            Ok(read) => {
                if read > max_len.saturating_sub(body.len()) {
                    return Err(());
                }
                body.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
}

pub fn apply_http_mitm_outcome_to_live_plain_http_request(
    request: &NativeExplicitHttpProxyRequest,
    outcome: &HttpMitmOutcome,
) -> NativePlainHttpRewriteApplication {
    let message = explicit_http_proxy_request_to_plain_http_message(request);
    apply_http_mitm_outcome_to_plain_http_message(&message, outcome)
}

pub fn serialize_explicit_http_proxy_request_for_upstream(
    request: &NativeExplicitHttpProxyRequest,
    rewrite_report: &NativePlainHttpRewriteReport,
) -> Vec<u8> {
    serialize_explicit_http_proxy_request_for_upstream_with_connection(
        request,
        rewrite_report,
        true,
    )
}

pub(crate) fn serialize_explicit_http_proxy_request_for_upstream_with_connection(
    request: &NativeExplicitHttpProxyRequest,
    rewrite_report: &NativePlainHttpRewriteReport,
    close_connection: bool,
) -> Vec<u8> {
    let origin_path = parse_script_absolute_url(&rewrite_report.url)
        .filter(|(_, target)| {
            target
                .target_host
                .eq_ignore_ascii_case(&request.target_host)
                && target.target_port == request.target_port
        })
        .map(|(_, target)| target.origin_path)
        .unwrap_or_else(|| request.origin_path.clone());
    let had_body_framing = request.headers.iter().any(|header| {
        header.key.eq_ignore_ascii_case("Content-Length")
            || header.key.eq_ignore_ascii_case("Transfer-Encoding")
    });
    let mut headers = rewrite_report.headers.clone();
    headers.retain(|header| !header.key.eq_ignore_ascii_case("Proxy-Connection"));
    // The proxy holds the whole body before it sends the request, so the
    // upstream has no reason to answer `100 Continue` first.
    remove_plain_http_header(&mut headers, "Expect");
    remove_plain_http_header(&mut headers, "Transfer-Encoding");
    remove_plain_http_header(&mut headers, "Content-Length");
    set_plain_http_header(
        &mut headers,
        "Host",
        &http_host_header_authority(&request.target_host, request.target_port),
    );
    set_plain_http_header(
        &mut headers,
        "Connection",
        if close_connection {
            "close"
        } else {
            "keep-alive"
        },
    );
    if !rewrite_report.body.is_empty() || had_body_framing {
        set_plain_http_header(
            &mut headers,
            "Content-Length",
            &rewrite_report.body.len().to_string(),
        );
    }

    let mut bytes =
        format!("{} {} {}\r\n", request.method, origin_path, request.version).into_bytes();
    write_http_headers_to_bytes(&mut bytes, &headers);
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&rewrite_report.body);
    bytes
}

pub fn serialize_plain_http_proxy_response(
    version: &str,
    rewrite_report: &NativePlainHttpRewriteReport,
) -> Vec<u8> {
    serialize_plain_http_proxy_response_with_connection(version, rewrite_report, true, "GET")
}

/// Serializes the response to a `request_method` request. A response that
/// has no body (to `HEAD`, or 1xx, 204, 304) is written without one: a
/// `HEAD` or 304 answer keeps the `Content-Length` it came with (the size
/// the full response would have), 1xx and 204 get none.
pub(crate) fn serialize_plain_http_proxy_response_with_connection(
    version: &str,
    rewrite_report: &NativePlainHttpRewriteReport,
    close_connection: bool,
    request_method: &str,
) -> Vec<u8> {
    let status_code = rewrite_report.final_status_code.unwrap_or(200);
    let bodiless = response_has_no_body(request_method, status_code);
    let mut headers = rewrite_report.headers.clone();
    if let Some(location) = &rewrite_report.redirect_location {
        set_plain_http_header(&mut headers, "Location", location);
    }
    let announced_length = headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case("Content-Length"))
        .map(|header| header.value.trim().to_string())
        .filter(|_| !(100..200).contains(&status_code) && status_code != 204);
    remove_plain_http_header(&mut headers, "Transfer-Encoding");
    remove_plain_http_header(&mut headers, "Content-Length");
    remove_plain_http_header(&mut headers, "Connection");
    set_plain_http_header(
        &mut headers,
        "Connection",
        if close_connection {
            "close"
        } else {
            "keep-alive"
        },
    );
    if !bodiless {
        set_plain_http_header(
            &mut headers,
            "Content-Length",
            &rewrite_report.body.len().to_string(),
        );
    } else if let Some(length) = announced_length {
        set_plain_http_header(&mut headers, "Content-Length", &length);
    }

    let mut bytes = format!(
        "{} {} {}\r\n",
        normalized_http_version(version),
        status_code,
        http_reason_phrase(status_code)
    )
    .into_bytes();
    write_http_headers_to_bytes(&mut bytes, &headers);
    bytes.extend_from_slice(b"\r\n");
    if !bodiless {
        bytes.extend_from_slice(&rewrite_report.body);
    }
    bytes
}

pub fn write_plain_http_proxy_upstream_request<W>(
    writer: &mut W,
    bytes: Vec<u8>,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
            "native plain HTTP proxy upstream request was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITE_FAILED_CODE,
            "native plain HTTP proxy upstream request could not be written",
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_plain_http_proxy_client_response<W>(
    writer: &mut W,
    bytes: Vec<u8>,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            "native plain HTTP proxy client response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITE_FAILED_CODE,
            "native plain HTTP proxy client response could not be written",
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_http_connect_established_response<W>(
    writer: &mut W,
    version: &str,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let bytes = format!(
        "{} 200 Connection Established\r\nProxy-Agent: NetworkCore\r\n\r\n",
        normalized_http_version(version)
    )
    .into_bytes();
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
            "native explicit HTTP proxy CONNECT tunnel was established through the configured SOCKS outbound",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE,
            "native explicit HTTP proxy CONNECT tunnel response could not be written",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}
