//! The loopback accept loop and the per-connection workers it runs.

use super::*;

/// First pause after an accept error that is not about one connection
/// (out of file descriptors or buffers); it doubles up to the maximum.
pub(crate) const ACCEPT_PAUSE_MIN: Duration = Duration::from_millis(50);
pub(crate) const ACCEPT_PAUSE_MAX: Duration = Duration::from_secs(1);

/// An accept error that means the listening descriptor itself is unusable:
/// EBADF (9 on every Unix) or ENOTSOCK, WSAEBADF or WSAENOTSOCK on Windows.
pub(crate) fn is_unusable_listener_error(error: &std::io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const UNUSABLE: [i32; 2] = [9, 88];
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    const UNUSABLE: [i32; 2] = [9, 38];
    #[cfg(windows)]
    const UNUSABLE: [i32; 2] = [10009, 10038];
    #[cfg(not(any(unix, windows)))]
    const UNUSABLE: [i32; 0] = [];
    error
        .raw_os_error()
        .is_some_and(|code| UNUSABLE.contains(&code))
}

pub(crate) fn run_loopback_tcp_accept_loop(
    listener: TcpListener,
    shutdown_rx: mpsc::Receiver<()>,
    accepted_connections: Arc<AtomicUsize>,
    pre_protocol_closed_connections: Arc<AtomicUsize>,
    relayed_connections: Arc<AtomicUsize>,
    identity: NativeLoopbackTcpAcceptLoopIdentity,
) -> NativeLoopbackTcpAcceptLoopShutdownReport {
    let mut diagnostics = Vec::new();
    let mut connection_workers = Vec::new();
    let mut accept_pause = ACCEPT_PAUSE_MIN;
    let mut resource_error_reported = false;

    loop {
        collect_finished_connection_workers(&mut connection_workers, &mut diagnostics);
        match shutdown_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        match listener.accept() {
            Ok((stream, _)) => {
                accept_pause = ACCEPT_PAUSE_MIN;
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                if connection_workers.len() >= MAX_CONCURRENT_ACCEPTED_CONNECTIONS {
                    let _ = stream.shutdown(Shutdown::Both);
                    pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);
                    diagnostics.push(runtime_warning(
                        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
                        "native loopback tcp accept loop reached the bounded concurrent connection limit",
                    ));
                    continue;
                }
                let worker_identity = identity.clone();
                let worker_pre_protocol_closed_connections =
                    Arc::clone(&pre_protocol_closed_connections);
                let worker_relayed_connections = Arc::clone(&relayed_connections);
                connection_workers.push(thread::spawn(move || {
                    if worker_identity.listener_kind == ListenerKind::Http {
                        handle_plain_http_proxy_accepted_connection(
                            stream,
                            worker_pre_protocol_closed_connections.as_ref(),
                            worker_relayed_connections.as_ref(),
                            &worker_identity.outbound_handler,
                            worker_identity.http_mitm_hook.as_ref(),
                            worker_identity.tls_mitm_ca_material.as_ref(),
                        )
                    } else {
                        read_socks5_greeting_and_close_accepted_connection(
                            stream,
                            worker_pre_protocol_closed_connections.as_ref(),
                            worker_relayed_connections.as_ref(),
                            &worker_identity.outbound_handler,
                            worker_identity.http_mitm_hook.as_ref(),
                            &worker_identity.local_host,
                            worker_identity.local_port,
                        )
                    }
                }));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                accept_pause = ACCEPT_PAUSE_MIN;
                thread::sleep(Duration::from_millis(10));
            }
            // One client reset its connection before it was accepted.
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::Interrupted
                ) => {}
            Err(error)
                if error.kind() != ErrorKind::InvalidInput
                    && !is_unusable_listener_error(&error) =>
            {
                // Out of file descriptors or buffers for a while: wait (the
                // shutdown request is still checked each round) instead of
                // stopping the listener for good.
                if !resource_error_reported {
                    resource_error_reported = true;
                    diagnostics.push(runtime_warning(
                        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_RETRYING_CODE,
                        "native loopback tcp accept loop is short of file descriptors or buffers and keeps retrying",
                    ));
                }
                thread::sleep(accept_pause);
                accept_pause = (accept_pause * 2).min(ACCEPT_PAUSE_MAX);
            }
            Err(_) => {
                diagnostics.push(engine_diagnostic(
                    DiagnosticSeverity::Error,
                    ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                    "native loopback tcp accept loop failed while accepting connections",
                    SOURCE_ENGINE_NATIVE_RUNTIME,
                ));
                break;
            }
        }
    }

    join_connection_workers(&mut connection_workers, &mut diagnostics);

    diagnostics.push(runtime_info(
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
        "native loopback tcp accept loop stopped",
    ));

    NativeLoopbackTcpAcceptLoopShutdownReport {
        listener_id: identity.listener_id,
        outbound_handler_id: identity.outbound_handler_id,
        local_host: identity.local_host,
        local_port: identity.local_port,
        accepted_connections: accepted_connections.load(Ordering::SeqCst),
        pre_protocol_closed_connections: pre_protocol_closed_connections.load(Ordering::SeqCst),
        relayed_connections: relayed_connections.load(Ordering::SeqCst),
        diagnostics,
    }
}

pub(crate) fn collect_finished_connection_workers(
    connection_workers: &mut Vec<JoinHandle<Vec<Diagnostic>>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut pending_workers = Vec::new();
    for worker in std::mem::take(connection_workers) {
        if worker.is_finished() {
            collect_connection_worker(worker, diagnostics);
        } else {
            pending_workers.push(worker);
        }
    }
    *connection_workers = pending_workers;
}

pub(crate) fn join_connection_workers(
    connection_workers: &mut Vec<JoinHandle<Vec<Diagnostic>>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for worker in std::mem::take(connection_workers) {
        collect_connection_worker(worker, diagnostics);
    }
}

pub(crate) fn collect_connection_worker(
    worker: JoinHandle<Vec<Diagnostic>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match worker.join() {
        Ok(connection_diagnostics) => diagnostics.extend(connection_diagnostics),
        Err(_) => diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Error,
            ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
            "native loopback tcp connection worker terminated unexpectedly",
            SOURCE_ENGINE_NATIVE_RUNTIME,
        )),
    }
}

pub(crate) fn handle_plain_http_proxy_accepted_connection(
    mut stream: TcpStream,
    pre_protocol_closed_connections: &AtomicUsize,
    relayed_connections: &AtomicUsize,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<&NativeTlsMitmCaMaterial>,
) -> Vec<Diagnostic> {
    let mut connection_handled = false;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
    )));

    let read_report = read_explicit_http_proxy_request(&mut stream);
    let mut diagnostics = read_report.diagnostics;
    if let Some(request) = read_report.request.as_ref() {
        if request.method.eq_ignore_ascii_case("CONNECT") {
            let (forwarded, forward_diagnostics) = forward_http_connect_tunnel_via_socks_outbound(
                &mut stream,
                request,
                outbound_handler,
                http_mitm_hook,
                tls_mitm_ca_material,
            );
            connection_handled = forwarded;
            diagnostics.extend(forward_diagnostics);
        } else if request.target_url.starts_with("https://") {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
                "native explicit HTTP proxy https absolute-form handling remains blocked; use CONNECT for the TLS foundation path",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            let response = plain_http_status_response(
                &request.version,
                501,
                b"NetworkCore explicit HTTP proxy only accepts HTTPS through CONNECT in this release.\n",
            );
            let write_report = write_plain_http_proxy_client_response(&mut stream, response);
            connection_handled = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
        } else {
            let request_message = explicit_http_proxy_request_to_plain_http_message(request);
            let request_rewrite_report = http_mitm_hook
                .map(|hook| hook.plan_plain_http(&request_message))
                .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&request_message));
            diagnostics.extend(request_rewrite_report.diagnostics.clone());
            record_plain_http_live_rewrite_diagnostic(&mut diagnostics, &request_rewrite_report);

            if request_rewrite_report.terminal_action.is_some() {
                let response = serialize_plain_http_proxy_response_with_connection(
                    &request.version,
                    &request_rewrite_report,
                    true,
                    &request.method,
                );
                let write_report = write_plain_http_proxy_client_response(&mut stream, response);
                connection_handled = diagnostics_contain_code(
                    &write_report.diagnostics,
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
                );
                diagnostics.extend(write_report.diagnostics);
            } else {
                let (forwarded, forward_diagnostics) =
                    forward_plain_http_proxy_request_via_socks_outbound(
                        &mut stream,
                        request,
                        &request_rewrite_report,
                        outbound_handler,
                        http_mitm_hook,
                    );
                connection_handled = forwarded;
                diagnostics.extend(forward_diagnostics);
            }
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
    if connection_handled {
        relayed_connections.fetch_add(1, Ordering::SeqCst);
    } else {
        pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);
        diagnostics.push(runtime_info(
            ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
            "native loopback tcp connection was closed before route and outbound handling",
        ));
    }

    diagnostics
}

pub(crate) fn forward_plain_http_proxy_request_via_socks_outbound(
    client_stream: &mut TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    request_rewrite_report: &NativePlainHttpRewriteReport,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
) -> (bool, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let target = explicit_http_proxy_request_to_socks5_target(request);
    let route_selection_report = select_socks5_route_outbound_behavior(&target, outbound_handler);
    diagnostics.extend(route_selection_report.diagnostics);
    let frame_report =
        build_socks5_outbound_connect_request_frame(&route_selection_report.behavior);
    diagnostics.extend(frame_report.diagnostics);
    let plan_report =
        plan_socks5_outbound_tcp_connection(&route_selection_report.behavior, &frame_report.frame);
    diagnostics.extend(plan_report.diagnostics);

    if let Some(plan) = plan_report.plan.as_ref() {
        let NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: outbound_stream,
            diagnostics: attempt_diagnostics,
        } = attempt_socks5_outbound_tcp_connection(plan);
        diagnostics.extend(attempt_diagnostics);
        if let Some(mut outbound_stream) = outbound_stream {
            let _ = outbound_stream.set_write_timeout(Some(Duration::from_millis(
                OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
            )));
            let write_report = write_socks5_outbound_connect_request(&mut outbound_stream, plan);
            let connect_request_written = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
            if connect_request_written {
                let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
                    OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                )));
                let read_report = read_socks5_outbound_connect_response(&mut outbound_stream);
                let response = read_report.response;
                diagnostics.extend(read_report.diagnostics);
                if let Some(response) = response.as_ref() {
                    let decision_report = decide_socks5_outbound_connect_response(response);
                    let decision = decision_report.decision;
                    diagnostics.extend(decision_report.diagnostics);
                    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision);
                    let readiness = readiness_report.readiness;
                    diagnostics.extend(readiness_report.diagnostics);
                    let data_relay_plan_report = plan_socks5_outbound_connect_data_relay(readiness);
                    let data_relay_plan = data_relay_plan_report.decision;
                    diagnostics.extend(data_relay_plan_report.diagnostics);

                    if data_relay_plan == NativeSocks5OutboundConnectDataRelayPlanDecision::Ready {
                        let request_bytes = serialize_explicit_http_proxy_request_for_upstream(
                            request,
                            request_rewrite_report,
                        );
                        let upstream_write_report = write_plain_http_proxy_upstream_request(
                            &mut outbound_stream,
                            request_bytes,
                        );
                        let upstream_request_written = diagnostics_contain_code(
                            &upstream_write_report.diagnostics,
                            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
                        );
                        diagnostics.extend(upstream_write_report.diagnostics);
                        if upstream_request_written {
                            // The socket's short connect timeout would cut a
                            // slow answer or one that arrives in pieces; the
                            // whole read gets the session's time instead.
                            let (response_read_report, interim) = {
                                let mut bounded_reader = NativeBoundedRead::new(
                                    &mut outbound_stream,
                                    Duration::from_millis(CONTROLLED_TLS_SESSION_TIMEOUT_MS),
                                );
                                read_plain_http_proxy_response_with_interim(
                                    &mut bounded_reader,
                                    &request.method,
                                )
                            };
                            let upstream_response = response_read_report.response;
                            diagnostics.extend(response_read_report.diagnostics);
                            if upstream_response.is_some() && !interim.is_empty() {
                                let _ = client_stream.write_all(&interim);
                            }
                            if let Some(upstream_response) = upstream_response.as_ref() {
                                let response_message =
                                    plain_http_proxy_response_to_plain_http_message(
                                        request,
                                        upstream_response,
                                    );
                                let response_rewrite_report = http_mitm_hook
                                    .map(|hook| hook.plan_plain_http(&response_message))
                                    .unwrap_or_else(|| {
                                        passthrough_plain_http_rewrite_report(&response_message)
                                    });
                                diagnostics.extend(response_rewrite_report.diagnostics.clone());
                                record_plain_http_live_rewrite_diagnostic(
                                    &mut diagnostics,
                                    &response_rewrite_report,
                                );
                                let client_response =
                                    serialize_plain_http_proxy_response_with_connection(
                                        &upstream_response.version,
                                        &response_rewrite_report,
                                        true,
                                        &request.method,
                                    );
                                let client_write_report = write_plain_http_proxy_client_response(
                                    client_stream,
                                    client_response,
                                );
                                let client_response_written = diagnostics_contain_code(
                                    &client_write_report.diagnostics,
                                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
                                );
                                diagnostics.extend(client_write_report.diagnostics);
                                let _ = outbound_stream.shutdown(Shutdown::Both);
                                return (client_response_written, diagnostics);
                            }
                        }
                    }
                }
            }
            let _ = outbound_stream.shutdown(Shutdown::Both);
        }
    }

    let response = plain_http_status_response(
        &request.version,
        502,
        b"NetworkCore plain HTTP proxy could not reach the configured SOCKS outbound.\n",
    );
    let write_report = write_plain_http_proxy_client_response(client_stream, response);
    let response_written = diagnostics_contain_code(
        &write_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    diagnostics.extend(write_report.diagnostics);

    (response_written, diagnostics)
}

pub(crate) fn run_controlled_tls_connect_http_exchange(
    client_stream: &TcpStream,
    outbound_stream: TcpStream,
    connect_request: &NativeExplicitHttpProxyRequest,
    downstream_server_config: Arc<ServerConfig>,
    upstream_client_config: Arc<ClientConfig>,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
) -> (bool, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let exchange = (|| -> Result<bool, String> {
        let session_timeout = Duration::from_millis(CONTROLLED_TLS_SESSION_TIMEOUT_MS);
        let _ = client_stream.set_read_timeout(Some(Duration::from_millis(
            CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS,
        )));
        let _ = client_stream.set_write_timeout(Some(session_timeout));
        let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
            CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS,
        )));
        let _ = outbound_stream.set_write_timeout(Some(session_timeout));
        let client_tls_stream = client_stream.try_clone().map_err(|error| {
            format!("controlled TLS client stream could not be cloned: {error}")
        })?;
        let server_name = ServerName::try_from(connect_request.target_host.as_str())
            .map_err(|error| format!("controlled TLS upstream authority is invalid: {error}"))?
            .to_owned();

        let client_alpn_protocols = peek_controlled_tls_client_alpn_protocols(client_stream);
        if client_alpn_protocols
            .iter()
            .any(|protocol| protocol.as_slice() == h2_mitm::ALPN_H2)
        {
            let negotiated = h2_mitm::run_controlled_tls_alpn_session(
                h2_mitm::NativeControlledTlsAlpnSession {
                    client_stream: client_tls_stream,
                    outbound_stream,
                    server_name,
                    connect_request,
                    downstream_server_config,
                    upstream_client_config,
                    client_alpn_protocols: &client_alpn_protocols,
                    http_mitm_hook,
                    session_timeout,
                },
                &mut diagnostics,
            );
            // The ALPN runtime switched the shared socket description to
            // non-blocking; hand the caller's handle back in blocking mode.
            let _ = client_stream.set_nonblocking(false);
            return negotiated;
        }

        let downstream_connection =
            ServerConnection::new(downstream_server_config).map_err(|error| {
                format!("controlled TLS downstream session could not initialize: {error}")
            })?;
        let mut downstream_tls = StreamOwned::new(downstream_connection, client_tls_stream);
        let upstream_connection = ClientConnection::new(upstream_client_config, server_name)
            .map_err(|error| {
                format!("controlled TLS upstream session could not initialize: {error}")
            })?;
        let mut upstream_tls = StreamOwned::new(upstream_connection, outbound_stream);
        run_controlled_tls_http1_exchanges(
            &mut downstream_tls,
            &mut upstream_tls,
            connect_request,
            http_mitm_hook,
            session_timeout,
            &mut diagnostics,
        )
    })();

    match exchange {
        Ok(response_written) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
                "native explicit HTTP proxy CONNECT completed a controlled TLS request/response exchange",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            (response_written, diagnostics)
        }
        Err(error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            (false, diagnostics)
        }
    }
}

pub(crate) fn run_controlled_tls_http1_exchanges<D, U>(
    downstream_tls: &mut D,
    upstream_tls: &mut U,
    connect_request: &NativeExplicitHttpProxyRequest,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    session_timeout: Duration,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool, String>
where
    D: Read + Write,
    U: Read + Write,
{
    let mut response_written = false;
    for exchange_index in 0..CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
        let decrypted_request_report = {
            let mut bounded_reader = NativeBoundedRead::new(downstream_tls, session_timeout);
            read_https_connect_http_request(&mut bounded_reader, connect_request)
        };
        let Some(decrypted_request) = decrypted_request_report.request else {
            if exchange_index == 0 {
                diagnostics.extend(decrypted_request_report.diagnostics);
                return Err(
                    "controlled TLS downstream session could not read a bounded decrypted HTTP request"
                        .to_string(),
                );
            }
            break;
        };
        diagnostics.extend(decrypted_request_report.diagnostics);

        let request_message = explicit_http_proxy_request_to_plain_http_message(&decrypted_request);
        let request_rewrite_report = http_mitm_hook
            .map(|hook| hook.plan_plain_http(&request_message))
            .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&request_message));
        diagnostics.extend(request_rewrite_report.diagnostics.clone());
        record_plain_http_live_rewrite_diagnostic(diagnostics, &request_rewrite_report);

        if request_rewrite_report.terminal_action.is_some() {
            let client_response = serialize_plain_http_proxy_response_with_connection(
                &decrypted_request.version,
                &request_rewrite_report,
                true,
                &decrypted_request.method,
            );
            let client_write_report =
                write_plain_http_proxy_client_response(downstream_tls, client_response);
            response_written = diagnostics_contain_code(
                &client_write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            );
            diagnostics.extend(client_write_report.diagnostics);
            break;
        }

        let request_close =
            http_message_requests_close(&decrypted_request.version, &decrypted_request.headers)
                || exchange_index + 1 == CONTROLLED_TLS_MAX_HTTP_EXCHANGES;
        let upstream_request = serialize_explicit_http_proxy_request_for_upstream_with_connection(
            &decrypted_request,
            &request_rewrite_report,
            request_close,
        );
        let upstream_write_report =
            write_plain_http_proxy_upstream_request(upstream_tls, upstream_request);
        let upstream_request_written = diagnostics_contain_code(
            &upstream_write_report.diagnostics,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
        );
        diagnostics.extend(upstream_write_report.diagnostics);
        if !upstream_request_written {
            return Err("controlled TLS upstream request write failed".to_string());
        }

        let (upstream_response_report, interim) = {
            let mut bounded_reader = NativeBoundedRead::new(upstream_tls, session_timeout);
            read_plain_http_proxy_response_with_interim(
                &mut bounded_reader,
                &decrypted_request.method,
            )
        };
        diagnostics.extend(upstream_response_report.diagnostics.clone());
        let upstream_response = upstream_response_report.response.ok_or_else(|| {
            "controlled TLS upstream session could not read a bounded HTTP response".to_string()
        })?;
        if !interim.is_empty() {
            downstream_tls
                .write_all(&interim)
                .map_err(|_| "controlled TLS downstream interim response write failed")?;
        }
        // A body that ran to the upstream's close leaves no connection for
        // another exchange.
        let response_close = request_close
            || http_message_requests_close(&upstream_response.version, &upstream_response.headers)
            || response_is_close_delimited(&decrypted_request.method, &upstream_response);
        let response_message =
            plain_http_proxy_response_to_plain_http_message(&decrypted_request, &upstream_response);
        let response_rewrite_report = http_mitm_hook
            .map(|hook| hook.plan_plain_http(&response_message))
            .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&response_message));
        diagnostics.extend(response_rewrite_report.diagnostics.clone());
        record_plain_http_live_rewrite_diagnostic(diagnostics, &response_rewrite_report);
        let client_response = serialize_plain_http_proxy_response_with_connection(
            &upstream_response.version,
            &response_rewrite_report,
            response_close,
            &decrypted_request.method,
        );
        let client_write_report =
            write_plain_http_proxy_client_response(downstream_tls, client_response);
        response_written = diagnostics_contain_code(
            &client_write_report.diagnostics,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
        );
        diagnostics.extend(client_write_report.diagnostics);
        if response_close {
            break;
        }
    }
    Ok(response_written)
}

pub(crate) fn peek_controlled_tls_client_alpn_protocols(client_stream: &TcpStream) -> Vec<Vec<u8>> {
    let mut buffer = [0_u8; TLS_CLIENT_HELLO_PEEK_MAX_BYTES];
    match client_stream.peek(&mut buffer) {
        Ok(bytes_read) => parse_tls_client_hello_metadata(&buffer[..bytes_read])
            .map(|metadata| metadata.alpn_protocols)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub(crate) fn forward_http_connect_tunnel_via_socks_outbound(
    client_stream: &mut TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<&NativeTlsMitmCaMaterial>,
) -> (bool, Vec<Diagnostic>) {
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(request);
    let mut diagnostics = foundation_report.diagnostics.clone();
    let target = explicit_http_proxy_request_to_socks5_target(request);
    let route_selection_report = select_socks5_route_outbound_behavior(&target, outbound_handler);
    diagnostics.extend(route_selection_report.diagnostics);
    let frame_report =
        build_socks5_outbound_connect_request_frame(&route_selection_report.behavior);
    diagnostics.extend(frame_report.diagnostics);
    let plan_report =
        plan_socks5_outbound_tcp_connection(&route_selection_report.behavior, &frame_report.frame);
    diagnostics.extend(plan_report.diagnostics);

    if let Some(plan) = plan_report.plan.as_ref() {
        let NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: outbound_stream,
            diagnostics: attempt_diagnostics,
        } = attempt_socks5_outbound_tcp_connection(plan);
        diagnostics.extend(attempt_diagnostics);
        if let Some(mut outbound_stream) = outbound_stream {
            let _ = outbound_stream.set_write_timeout(Some(Duration::from_millis(
                OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
            )));
            let write_report = write_socks5_outbound_connect_request(&mut outbound_stream, plan);
            let connect_request_written = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
            if connect_request_written {
                let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
                    OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                )));
                let read_report = read_socks5_outbound_connect_response(&mut outbound_stream);
                let response = read_report.response;
                diagnostics.extend(read_report.diagnostics);
                if let Some(response) = response.as_ref() {
                    let decision_report = decide_socks5_outbound_connect_response(response);
                    let decision = decision_report.decision;
                    diagnostics.extend(decision_report.diagnostics);
                    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision);
                    let readiness = readiness_report.readiness;
                    diagnostics.extend(readiness_report.diagnostics);
                    let data_relay_plan_report = plan_socks5_outbound_connect_data_relay(readiness);
                    let data_relay_plan = data_relay_plan_report.decision;
                    diagnostics.extend(data_relay_plan_report.diagnostics);

                    if data_relay_plan == NativeSocks5OutboundConnectDataRelayPlanDecision::Ready {
                        let connect_response = write_http_connect_established_response(
                            client_stream,
                            &request.version,
                        );
                        let tunnel_established = diagnostics_contain_code(
                            &connect_response.diagnostics,
                            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
                        );
                        diagnostics.extend(connect_response.diagnostics);
                        if tunnel_established {
                            // Only `[MITM]` hosts are decrypted, as on the
                            // other data planes; the rest are relayed.
                            let tls_mitm_ca_material = tls_mitm_ca_material.filter(|_| {
                                let intercept = http_mitm_hook.is_some_and(|hook| {
                                    hook.intercepts_tls_host(&request.target_host)
                                });
                                if !intercept {
                                    diagnostics.push(engine_diagnostic(
                                        DiagnosticSeverity::Info,
                                        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_MITM_HOSTNAME_BYPASSED_CODE,
                                        "native explicit HTTP proxy relayed CONNECT to a host outside the MITM hostname list",
                                        SOURCE_ENGINE_NATIVE_MITM,
                                    ));
                                }
                                intercept
                            });
                            let wait_for_complete_client_hello = tls_mitm_ca_material.is_some();
                            let client_hello_report =
                                observe_http_connect_tls_client_hello_from_stream(
                                    client_stream,
                                    request,
                                    wait_for_complete_client_hello,
                                );
                            diagnostics.extend(client_hello_report.diagnostics.clone());
                            if let Some(tls_mitm_ca_material) = tls_mitm_ca_material {
                                let termination_plan =
                                    plan_explicit_http_connect_controlled_tls_termination(
                                        request,
                                        &foundation_report,
                                        &client_hello_report,
                                        tls_mitm_ca_material.certificate_pem_ready(),
                                        tls_mitm_ca_material.private_key_pem_ready(),
                                    );
                                diagnostics.extend(termination_plan.diagnostics.clone());
                                let leaf_certificate_report =
                                    issue_controlled_tls_termination_leaf_certificate(
                                        &termination_plan,
                                        tls_mitm_ca_material.certificate_pem(),
                                        tls_mitm_ca_material.private_key_pem(),
                                    );
                                diagnostics.extend(leaf_certificate_report.diagnostics.clone());
                                // The ClientHello was only peeked at, so until
                                // the handshake starts the connection can still
                                // be relayed as it is: a host that cannot be
                                // terminated (no SNI or another one, ECH's
                                // outer name, not TLS, no leaf) passes through
                                // instead of being closed.
                                let configs =
                                    leaf_certificate_report.material.as_ref().and_then(|leaf| {
                                        let downstream =
                                            build_controlled_tls_termination_server_config(leaf);
                                        diagnostics.extend(downstream.diagnostics.clone());
                                        let downstream = downstream.server_config?;
                                        let upstream =
                                            build_controlled_tls_upstream_client_config();
                                        diagnostics.extend(upstream.diagnostics.clone());
                                        Some((downstream, upstream.client_config?))
                                    });
                                if let Some((downstream_server_config, upstream_client_config)) =
                                    configs
                                {
                                    let (exchange_completed, exchange_diagnostics) =
                                        run_controlled_tls_connect_http_exchange(
                                            client_stream,
                                            outbound_stream,
                                            request,
                                            downstream_server_config,
                                            upstream_client_config,
                                            http_mitm_hook,
                                        );
                                    diagnostics.extend(exchange_diagnostics);
                                    return (exchange_completed, diagnostics);
                                }
                                diagnostics.push(engine_diagnostic(
                                    DiagnosticSeverity::Warning,
                                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_MITM_PASSTHROUGH_CODE,
                                    "native explicit HTTP proxy relayed a CONNECT it could not terminate without decryption",
                                    SOURCE_ENGINE_NATIVE_MITM,
                                ));
                            }
                            let relay_report = relay_socks5_outbound_connect_tcp_streams(
                                client_stream,
                                &outbound_stream,
                            );
                            let tunnel_relayed =
                                diagnostics_contain_data_relay_completed(&relay_report.diagnostics);
                            diagnostics.extend(relay_report.diagnostics);
                            let _ = outbound_stream.shutdown(Shutdown::Both);
                            return (tunnel_relayed, diagnostics);
                        }
                    }
                }
            }
            let _ = outbound_stream.shutdown(Shutdown::Both);
        }
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Warning,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE,
        "native explicit HTTP proxy CONNECT tunnel could not be established through the configured SOCKS outbound",
        SOURCE_ENGINE_NATIVE_MITM,
    ));
    let response = plain_http_status_response(
        &request.version,
        502,
        b"NetworkCore explicit HTTP CONNECT tunnel could not reach the configured SOCKS outbound.\n",
    );
    let write_report = write_plain_http_proxy_client_response(client_stream, response);
    let response_written = diagnostics_contain_code(
        &write_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    diagnostics.extend(write_report.diagnostics);

    (response_written, diagnostics)
}

pub(crate) fn observe_http_connect_tls_client_hello_from_stream(
    client_stream: &TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    wait_for_complete_client_hello: bool,
) -> NativeTlsClientHelloObservationReport {
    let mut buffer = [0_u8; TLS_CLIENT_HELLO_PEEK_MAX_BYTES];
    let prior_timeout = client_stream.read_timeout().ok().flatten();
    if wait_for_complete_client_hello {
        let _ = client_stream.set_read_timeout(Some(Duration::from_millis(
            ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
        )));
    }
    let started_at = Instant::now();
    let report = loop {
        let bytes = match client_stream.peek(&mut buffer) {
            Ok(bytes_read) => &buffer[..bytes_read],
            Err(error) if error.kind() == ErrorKind::WouldBlock => &buffer[..0],
            Err(error) if error.kind() == ErrorKind::TimedOut => &buffer[..0],
            Err(_) => &buffer[..0],
        };
        let report = observe_explicit_http_connect_tls_client_hello(request, bytes);
        if report.client_hello_observed
            || !wait_for_complete_client_hello
            || started_at.elapsed()
                >= Duration::from_millis(TLS_CLIENT_HELLO_OBSERVATION_TIMEOUT_MS)
        {
            break report;
        }
        thread::sleep(Duration::from_millis(TLS_CLIENT_HELLO_OBSERVATION_POLL_MS));
    };
    if wait_for_complete_client_hello {
        let _ = client_stream.set_read_timeout(prior_timeout);
    }

    report
}

pub(crate) fn record_plain_http_live_rewrite_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    rewrite_report: &NativePlainHttpRewriteReport,
) {
    if rewrite_report.applied {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
            "native explicit HTTP proxy applied a plain HTTP MITM rewrite report",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }
}

pub(crate) fn read_socks5_greeting_and_close_accepted_connection(
    mut stream: TcpStream,
    pre_protocol_closed_connections: &AtomicUsize,
    relayed_connections: &AtomicUsize,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    local_host: &str,
    local_port: u16,
) -> Vec<Diagnostic> {
    let mut connection_relayed = false;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let read_report = read_socks5_greeting(&mut stream);
    let mut diagnostics = read_report.diagnostics;
    if let Some(greeting) = read_report
        .greeting
        .as_ref()
        .filter(|greeting| greeting.version == SOCKS5_VERSION && !greeting.auth_methods.is_empty())
    {
        let selection_report = select_socks5_auth_method(greeting);
        let decision = selection_report.decision;
        diagnostics.extend(selection_report.diagnostics);
        diagnostics.extend(write_socks5_auth_method_response(&mut stream, decision).diagnostics);
        if decision == NativeSocks5AuthMethodDecision::NoAuthenticationRequired {
            let NativeSocks5CommandHeaderReadReport {
                command_header,
                diagnostics: command_diagnostics,
            } = read_socks5_command_header(&mut stream);
            diagnostics.extend(command_diagnostics);
            if let Some(command_header) = command_header
                .as_ref()
                .filter(|command_header| socks5_command_header_valid(command_header))
            {
                let support_report = reject_unsupported_socks5_command(command_header);
                let command_decision = support_report.decision;
                diagnostics.extend(support_report.diagnostics);
                if command_decision == NativeSocks5CommandDecision::Connect {
                    let NativeSocks5ConnectTargetReadReport {
                        target,
                        diagnostics: target_diagnostics,
                    } = read_socks5_connect_target(&mut stream, command_header);
                    diagnostics.extend(target_diagnostics);
                    if let Some(target) = target
                        .as_ref()
                        .filter(|target| socks5_connect_target_valid(target))
                    {
                        let mut rejected_by_http_mitm = false;
                        if let Some(hook) = http_mitm_hook {
                            let mitm_plan_report = hook.plan_socks5_connect(
                                socks5_connect_http_mitm_request_id(target),
                                target,
                            );
                            let browser_capture_proof_token =
                                native_socks5_connect_browser_capture_proof_token(
                                    target, "socks5", local_host, local_port,
                                );
                            rejected_by_http_mitm = mitm_plan_report
                                .outcome
                                .as_ref()
                                .map(http_mitm_outcome_rejects)
                                .unwrap_or(false);
                            diagnostics.extend(mitm_plan_report.diagnostics);
                            diagnostics.push(engine_diagnostic(
                                DiagnosticSeverity::Info,
                                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE,
                                format!(
                                    "native SOCKS5 CONNECT browser capture proof token {browser_capture_proof_token} observed for target {} via socks5://{}:{}",
                                    socks5_target_header_authority(target),
                                    local_host,
                                    local_port
                                ),
                                SOURCE_ENGINE_NATIVE_MITM,
                            ));
                            if rejected_by_http_mitm {
                                diagnostics.push(engine_diagnostic(
                                    DiagnosticSeverity::Info,
                                    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE,
                                    "native SOCKS5 CONNECT was rejected by the MITM plugin plan",
                                    SOURCE_ENGINE_NATIVE_MITM,
                                ));
                                let failure_response_report =
                                    write_http_mitm_rejected_socks5_connect_failure_response(
                                        &mut stream,
                                    );
                                diagnostics.extend(failure_response_report.diagnostics);
                            }
                        }

                        if !rejected_by_http_mitm {
                            let mut failure_response_required = true;
                            let route_selection_report =
                                select_socks5_route_outbound_behavior(target, outbound_handler);
                            diagnostics.extend(route_selection_report.diagnostics);
                            let frame_report = build_socks5_outbound_connect_request_frame(
                                &route_selection_report.behavior,
                            );
                            diagnostics.extend(frame_report.diagnostics);
                            let plan_report = plan_socks5_outbound_tcp_connection(
                                &route_selection_report.behavior,
                                &frame_report.frame,
                            );
                            diagnostics.extend(plan_report.diagnostics);
                            if let Some(plan) = plan_report.plan.as_ref() {
                                let NativeSocks5OutboundTcpConnectionAttemptReport {
                                    stream: outbound_stream,
                                    diagnostics: attempt_diagnostics,
                                } = attempt_socks5_outbound_tcp_connection(plan);
                                diagnostics.extend(attempt_diagnostics);
                                if let Some(mut outbound_stream) = outbound_stream {
                                    let _ = outbound_stream.set_write_timeout(Some(
                                        Duration::from_millis(
                                            OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
                                        ),
                                    ));
                                    let write_report = write_socks5_outbound_connect_request(
                                        &mut outbound_stream,
                                        plan,
                                    );
                                    let connect_request_written =
                                        write_report.diagnostics.iter().any(|diagnostic| {
                                            diagnostic.code
                                                == ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE
                                        });
                                    diagnostics.extend(write_report.diagnostics);
                                    if connect_request_written {
                                        let _ = outbound_stream.set_read_timeout(Some(
                                            Duration::from_millis(
                                                OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                                            ),
                                        ));
                                        let read_report = read_socks5_outbound_connect_response(
                                            &mut outbound_stream,
                                        );
                                        let response = read_report.response;
                                        diagnostics.extend(read_report.diagnostics);
                                        if let Some(response) = response.as_ref() {
                                            let decision_report =
                                                decide_socks5_outbound_connect_response(response);
                                            let decision = decision_report.decision;
                                            diagnostics.extend(decision_report.diagnostics);
                                            let readiness_report =
                                                assess_socks5_outbound_connect_relay_readiness(
                                                    decision,
                                                );
                                            let readiness = readiness_report.readiness;
                                            diagnostics.extend(readiness_report.diagnostics);
                                            let data_relay_plan_report =
                                                plan_socks5_outbound_connect_data_relay(readiness);
                                            let data_relay_plan = data_relay_plan_report.decision;
                                            diagnostics.extend(data_relay_plan_report.diagnostics);
                                            let client_success_readiness_report =
                                                assess_socks5_outbound_connect_client_success_response_readiness(
                                                    data_relay_plan,
                                                );
                                            let client_success_readiness =
                                                client_success_readiness_report.readiness;
                                            diagnostics.extend(
                                                client_success_readiness_report.diagnostics,
                                            );
                                            let write_plan_report =
                                                plan_socks5_outbound_connect_client_success_response_write(
                                                    client_success_readiness,
                                                );
                                            let write_plan = write_plan_report.decision;
                                            diagnostics.extend(write_plan_report.diagnostics);
                                            let write_plan_ready = matches!(
                                                write_plan,
                                                NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Ready
                                            );
                                            if write_plan_ready {
                                                failure_response_required = false;
                                                let client_success_write_report =
                                                    write_socks5_outbound_connect_client_success_response(
                                                        &mut stream,
                                                        response,
                                                    );
                                                let client_success_write_diagnostics =
                                                    client_success_write_report.diagnostics;
                                                let client_success_response_written =
                                                    diagnostics_contain_client_success_written(
                                                        &client_success_write_diagnostics,
                                                    );
                                                diagnostics
                                                    .extend(client_success_write_diagnostics);
                                                if client_success_response_written {
                                                    let data_relay_report =
                                                        relay_socks5_outbound_connect_tcp_streams(
                                                            &stream,
                                                            &outbound_stream,
                                                        );
                                                    let data_relay_diagnostics =
                                                        data_relay_report.diagnostics;
                                                    connection_relayed =
                                                        diagnostics_contain_data_relay_completed(
                                                            &data_relay_diagnostics,
                                                        );
                                                    diagnostics.extend(data_relay_diagnostics);
                                                }
                                            }
                                        }
                                    }
                                    let _ = outbound_stream.shutdown(Shutdown::Both);
                                }
                            }
                            if failure_response_required {
                                diagnostics.extend(
                                    reject_unwired_socks5_route_outbound(target).diagnostics,
                                );
                                let failure_response_report =
                                    write_unwired_socks5_connect_failure_response(&mut stream);
                                diagnostics.extend(failure_response_report.diagnostics);
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    if connection_relayed {
        relayed_connections.fetch_add(1, Ordering::SeqCst);
    } else {
        pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);

        diagnostics.push(runtime_info(
            ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
            "native loopback tcp connection was closed before route and outbound handling",
        ));
    }

    diagnostics
}
