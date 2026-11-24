//! TLS MITM on CONNECT: plans, controlled termination, leaf certificates
//! and HTTPS rewrite previews.

use super::*;

pub fn plan_socks5_connect_http_mitm(
    request_id: impl Into<String>,
    target: &NativeSocks5ConnectTarget,
    plugin_instance: &PluginInstance,
    plugin_service: &dyn MitmPluginService,
) -> NativeSocks5ConnectHttpMitmPlanReport {
    let request_id = request_id.into();
    let target_host = socks5_target_host(target);
    let target_port = target.port;
    let url = socks5_connect_http_mitm_url(target);
    let host_header = socks5_target_header_authority(target);
    let event = HttpMitmEvent {
        request_id: request_id.clone(),
        url: url.clone(),
        method: Some("CONNECT".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![
            MetadataEntry {
                key: "host".to_string(),
                value: host_header,
            },
            MetadataEntry {
                key: "networkcore.connect_target_host".to_string(),
                value: target_host.clone(),
            },
            MetadataEntry {
                key: "networkcore.connect_target_port".to_string(),
                value: target_port.to_string(),
            },
        ],
        body: Vec::new(),
    };
    let mut diagnostics = vec![engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE,
        "native SOCKS5 CONNECT target was mapped to a rich HTTP MITM event",
        SOURCE_ENGINE_NATIVE_MITM,
    )];

    match plugin_service.handle_http_mitm_event(plugin_instance, &event) {
        Ok(outcome) => {
            let audits = outcome.audits.clone();
            let plan_requires_application = http_mitm_outcome_requires_application(&outcome);
            diagnostics.extend(outcome.diagnostics.clone());
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE,
                "native SOCKS5 CONNECT MITM plugin plan was produced",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            if plan_requires_application {
                diagnostics.push(engine_diagnostic(
                    DiagnosticSeverity::Warning,
                    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE,
                    "native HTTP/TLS data plane has not applied the MITM plugin plan yet",
                    SOURCE_ENGINE_NATIVE_MITM,
                ));
            }

            NativeSocks5ConnectHttpMitmPlanReport {
                request_id,
                target_host,
                target_port,
                url,
                event,
                outcome: Some(outcome),
                applied: false,
                audits,
                diagnostics,
            }
        }
        Err(_error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_FAILED_CODE,
                "native SOCKS5 CONNECT MITM plugin plan failed",
                SOURCE_ENGINE_NATIVE_MITM,
            ));

            NativeSocks5ConnectHttpMitmPlanReport {
                request_id,
                target_host,
                target_port,
                url,
                event,
                outcome: None,
                applied: false,
                audits: Vec::new(),
                diagnostics,
            }
        }
    }
}

pub fn plan_explicit_http_connect_tls_mitm_foundation(
    request: &NativeExplicitHttpProxyRequest,
) -> NativeTlsMitmFoundationReport {
    let connect_request = request.method.eq_ignore_ascii_case("CONNECT");
    let target_url = if request.target_url.starts_with("https://") {
        request.target_url.clone()
    } else {
        let authority = http_url_authority(&request.target_host, request.target_port, 443);
        format!("https://{authority}/")
    };
    let mut diagnostics = Vec::new();

    if connect_request {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE,
            "native explicit HTTP proxy CONNECT TLS foundation can establish a bounded tunnel through the configured SOCKS outbound",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    } else {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
            "native explicit HTTP proxy TLS foundation requires a CONNECT request",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeTlsMitmFoundationReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        target_url,
        connect_tunnel_ready: connect_request,
        downstream_tls_termination_ready: false,
        upstream_tls_forwarding_ready: connect_request,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        diagnostics,
    }
}

pub fn observe_explicit_http_connect_tls_client_hello(
    request: &NativeExplicitHttpProxyRequest,
    client_hello: &[u8],
) -> NativeTlsClientHelloObservationReport {
    let metadata = parse_tls_client_hello_metadata(client_hello);
    let (client_hello_observed, sni_hostname, tls_record_version, tls_handshake_version) =
        match metadata {
            Some(metadata) => (
                true,
                metadata.sni_hostname,
                Some(metadata.tls_record_version),
                Some(metadata.tls_handshake_version),
            ),
            None => (false, None, None, None),
        };
    let diagnostic = if client_hello_observed {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE,
            "native explicit HTTP proxy CONNECT TLS ClientHello was observed before pass-through relay",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE,
            "native explicit HTTP proxy CONNECT TLS ClientHello was not available in the bounded pre-relay peek",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativeTlsClientHelloObservationReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        client_hello_observed,
        sni_hostname,
        tls_record_version,
        tls_handshake_version,
        downstream_tls_termination_ready: false,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        diagnostics: vec![diagnostic],
    }
}

pub fn plan_explicit_http_connect_controlled_tls_termination(
    request: &NativeExplicitHttpProxyRequest,
    foundation: &NativeTlsMitmFoundationReport,
    client_hello: &NativeTlsClientHelloObservationReport,
    ca_certificate_pem_ready: bool,
    ca_private_key_pem_ready: bool,
) -> NativeControlledTlsTerminationPlanReport {
    let sni_authority_matches = client_hello.client_hello_observed
        && tls_sni_matches_connect_authority(
            &request.target_host,
            client_hello.sni_hostname.as_deref(),
        );
    let downstream_tls_termination_plan_ready = request.method.eq_ignore_ascii_case("CONNECT")
        && foundation.connect_tunnel_ready
        && foundation.upstream_tls_forwarding_ready
        && client_hello.client_hello_observed
        && sni_authority_matches
        && ca_certificate_pem_ready
        && ca_private_key_pem_ready;
    let mut diagnostics = Vec::new();
    if client_hello.client_hello_observed {
        diagnostics.push(engine_diagnostic(
            if sni_authority_matches {
                DiagnosticSeverity::Info
            } else {
                DiagnosticSeverity::Warning
            },
            if sni_authority_matches {
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE
            } else {
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE
            },
            if sni_authority_matches {
                "native explicit HTTP proxy CONNECT authority matches the observed TLS SNI hostname"
            } else {
                "native explicit HTTP proxy CONNECT controlled TLS termination is deferred because the observed TLS SNI hostname does not match the CONNECT authority"
            },
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }
    diagnostics.push(if downstream_tls_termination_plan_ready {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE,
            "native explicit HTTP proxy CONNECT controlled TLS termination plan is ready with observed ClientHello and NetworkCore CA material",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE,
            "native explicit HTTP proxy CONNECT controlled TLS termination is deferred until CONNECT tunnel, ClientHello, matching authority, and NetworkCore CA material are all ready",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    });

    NativeControlledTlsTerminationPlanReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        target_url: foundation.target_url.clone(),
        connect_tunnel_ready: foundation.connect_tunnel_ready,
        client_hello_observed: client_hello.client_hello_observed,
        sni_hostname: client_hello.sni_hostname.clone(),
        tls_record_version: client_hello.tls_record_version.clone(),
        tls_handshake_version: client_hello.tls_handshake_version.clone(),
        ca_certificate_pem_ready,
        ca_private_key_pem_ready,
        downstream_tls_termination_plan_ready,
        upstream_tls_forwarding_ready: foundation.upstream_tls_forwarding_ready,
        live_https_decryption_ready: false,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        diagnostics,
    }
}

pub fn issue_controlled_tls_termination_leaf_certificate(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    ca_certificate_pem: &str,
    ca_private_key_pem: &str,
) -> NativeTlsLeafCertificateIssueReport {
    let authority = termination_plan
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let sni_authority_matches =
        tls_sni_matches_connect_authority(&authority, termination_plan.sni_hostname.as_deref());
    let certificate_issue_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.ca_certificate_pem_ready
        && termination_plan.ca_private_key_pem_ready
        && sni_authority_matches
        && !authority.is_empty();

    if !certificate_issue_ready {
        return NativeTlsLeafCertificateIssueReport {
            authority,
            issued: false,
            material: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE,
                "native explicit HTTP proxy CONNECT leaf certificate issuance is deferred until the controlled TLS plan, CA material, and matching authority are ready",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        };
    }

    let material = (|| {
        let issuer_key = KeyPair::from_pem(ca_private_key_pem).map_err(|error| {
            format!("NetworkCore CA private key could not be parsed for leaf issuance: {error}")
        })?;
        let issuer = Issuer::from_ca_cert_pem(ca_certificate_pem, issuer_key).map_err(|error| {
            format!("NetworkCore CA certificate could not be parsed for leaf issuance: {error}")
        })?;
        let mut leaf_params = CertificateParams::new(vec![authority.clone()]).map_err(|error| {
            format!("TLS leaf certificate authority could not be encoded: {error}")
        })?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, authority.clone());
        distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
        leaf_params.distinguished_name = distinguished_name;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate()
            .map_err(|error| format!("TLS leaf private key could not be generated: {error}"))?;
        let leaf_certificate = leaf_params.signed_by(&leaf_key, &issuer).map_err(|error| {
            format!("TLS leaf certificate could not be signed by the NetworkCore CA: {error}")
        })?;

        Ok::<NativeTlsLeafCertificateMaterial, String>(NativeTlsLeafCertificateMaterial {
            authority: authority.clone(),
            certificate_pem: leaf_certificate.pem(),
            private_key_pem: leaf_key.serialize_pem(),
            certificate_der: leaf_certificate.der().as_ref().to_vec(),
            private_key_der: leaf_key.serialize_der(),
        })
    })();

    match material {
        Ok(material) => NativeTlsLeafCertificateIssueReport {
            authority,
            issued: true,
            material: Some(material),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE,
                "native explicit HTTP proxy CONNECT issued an authority-bound TLS leaf certificate from the configured NetworkCore CA",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsLeafCertificateIssueReport {
            authority,
            issued: false,
            material: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn build_controlled_tls_termination_server_config(
    material: &NativeTlsLeafCertificateMaterial,
) -> NativeTlsServerConfigBuildReport {
    let authority = material
        .authority
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let server_config = (|| {
        if authority.is_empty()
            || material.certificate_der.is_empty()
            || material.private_key_der.is_empty()
        {
            return Err("controlled TLS server configuration requires authority-bound leaf certificate and private key material".to_string());
        }

        let certificate_chain = vec![CertificateDer::from(material.certificate_der.clone())];
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.private_key_der.clone()));
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| format!("controlled TLS protocol configuration failed: {error}"))?
                .with_no_client_auth()
                .with_single_cert(certificate_chain, private_key)
                .map_err(|error| {
                    format!("controlled TLS server certificate configuration failed: {error}")
                })?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(server_config))
    })();

    match server_config {
        Ok(server_config) => NativeTlsServerConfigBuildReport {
            authority,
            server_config_ready: true,
            server_config: Some(server_config),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE,
                "native explicit HTTP proxy CONNECT built a rustls downstream server configuration from authority-bound leaf material",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsServerConfigBuildReport {
            authority,
            server_config_ready: false,
            server_config: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn build_controlled_tls_upstream_client_config() -> NativeTlsUpstreamClientConfigBuildReport {
    let client_config = (|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if roots.is_empty() {
            return Err(
                "controlled TLS upstream configuration has no trusted web PKI roots".to_string(),
            );
        }

        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| {
                    format!("controlled TLS upstream protocol configuration failed: {error}")
                })?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(client_config))
    })();

    match client_config {
        Ok(client_config) => NativeTlsUpstreamClientConfigBuildReport {
            client_config_ready: true,
            client_config: Some(client_config),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE,
                "native explicit HTTP proxy CONNECT built a rustls upstream client configuration with web PKI roots",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsUpstreamClientConfigBuildReport {
            client_config_ready: false,
            client_config: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn plan_and_apply_https_request_rewrite_preview(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativeHttpsRequestRewritePreviewReport {
    let request_phase = matches!(message.phase, HttpMitmPhase::Request);
    let https_target = message.url.to_ascii_lowercase().starts_with("https://");
    let preview_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.upstream_tls_forwarding_ready
        && request_phase
        && https_target;
    let mut diagnostics = Vec::new();

    if !preview_ready {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS request rewrite preview is deferred until controlled TLS termination plan and request-phase HTTPS input are ready",
            SOURCE_ENGINE_NATIVE_MITM,
        ));

        return NativeHttpsRequestRewritePreviewReport {
            request_id: message.request_id.clone(),
            target_host: termination_plan.target_host.clone(),
            target_port: termination_plan.target_port,
            target_url: termination_plan.target_url.clone(),
            controlled_tls_termination_plan_ready: termination_plan
                .downstream_tls_termination_plan_ready,
            https_request_rewrite_preview_ready: false,
            applied: false,
            terminal_action: None,
            final_status_code: message.status_code,
            redirect_location: None,
            header_mutation_count: 0,
            body_mutation_deferred: outcome.body_mutation.is_some(),
            https_response_rewrite_preview_ready: false,
            https_response_rewrite_ready: false,
            script_dispatch_ready: false,
            script_dispatch_deferred: outcome.script_dispatch.is_some(),
            headers: message.headers.clone(),
            body: message.body.clone(),
            diagnostics,
        };
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE,
        "native explicit HTTP proxy HTTPS request rewrite preview is ready for reject, redirect, and request header mutation",
        SOURCE_ENGINE_NATIVE_MITM,
    ));

    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
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
        }
        HttpMitmAction::Respond {
            status_code,
            headers: response_headers,
            body: response_body,
        } => {
            applied = true;
            terminal_action = Some(LOCAL_RESPONSE_TERMINAL_ACTION.to_string());
            final_status_code = Some(*status_code);
            headers = local_response_headers(response_headers, response_body.len());
            body = response_body.clone();
        }
    }

    let mut header_mutation_count = 0;
    if terminal_action.is_none() {
        header_mutation_count =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        applied = applied || header_mutation_count > 0;
    }

    let body_mutation_deferred = outcome.body_mutation.is_some();
    let script_dispatch_deferred = outcome.script_dispatch.is_some();
    if script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS request rewrite preview recorded script dispatch but JavaScript execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeHttpsRequestRewritePreviewReport {
        request_id: message.request_id.clone(),
        target_host: termination_plan.target_host.clone(),
        target_port: termination_plan.target_port,
        target_url: termination_plan.target_url.clone(),
        controlled_tls_termination_plan_ready: termination_plan
            .downstream_tls_termination_plan_ready,
        https_request_rewrite_preview_ready: true,
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        header_mutation_count,
        body_mutation_deferred,
        https_response_rewrite_preview_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        script_dispatch_deferred,
        headers,
        body,
        diagnostics,
    }
}

pub fn plan_and_apply_https_response_rewrite_preview(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativeHttpsResponseRewritePreviewReport {
    let response_phase = matches!(message.phase, HttpMitmPhase::Response);
    let https_target = message.url.to_ascii_lowercase().starts_with("https://");
    let preview_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.upstream_tls_forwarding_ready
        && response_phase
        && https_target;
    let mut diagnostics = Vec::new();

    if !preview_ready {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS response rewrite preview is deferred until controlled TLS termination plan and response-phase HTTPS input are ready",
            SOURCE_ENGINE_NATIVE_MITM,
        ));

        return NativeHttpsResponseRewritePreviewReport {
            request_id: message.request_id.clone(),
            target_host: termination_plan.target_host.clone(),
            target_port: termination_plan.target_port,
            target_url: termination_plan.target_url.clone(),
            controlled_tls_termination_plan_ready: termination_plan
                .downstream_tls_termination_plan_ready,
            https_response_rewrite_preview_ready: false,
            applied: false,
            terminal_action: None,
            final_status_code: message.status_code,
            redirect_location: None,
            header_mutation_count: 0,
            content_type: plain_http_header_value(&message.headers, "Content-Type"),
            content_type_guard_ready: https_response_body_content_type_guard_ready(
                &message.headers,
            ),
            body_size_bytes: message.body.len(),
            body_size_limit_bytes: HTTP_PROXY_MAX_BODY_BYTES,
            body_buffering_guard_ready: https_response_body_buffering_guard_ready(
                &message.body,
                outcome
                    .body_mutation
                    .as_ref()
                    .map(|mutation| mutation.body.as_slice()),
            ),
            body_mutated: false,
            body_mutation_deferred: outcome.body_mutation.is_some(),
            https_request_rewrite_preview_ready: false,
            https_response_rewrite_ready: false,
            script_dispatch_ready: false,
            script_dispatch_deferred: outcome.script_dispatch.is_some(),
            headers: message.headers.clone(),
            body: message.body.clone(),
            diagnostics,
        };
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE,
        "native explicit HTTP proxy HTTPS response rewrite preview is ready for reject, redirect, response header mutation, and response body mutation",
        SOURCE_ENGINE_NATIVE_MITM,
    ));

    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;
    let mut body_mutated = false;
    let mut body_mutation_deferred = outcome.body_mutation.is_some();

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
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
        }
        HttpMitmAction::Respond {
            status_code,
            headers: response_headers,
            body: response_body,
        } => {
            applied = true;
            terminal_action = Some(LOCAL_RESPONSE_TERMINAL_ACTION.to_string());
            final_status_code = Some(*status_code);
            headers = local_response_headers(response_headers, response_body.len());
            body = response_body.clone();
        }
    }

    let mut header_mutation_count = 0;
    if terminal_action.is_none() {
        header_mutation_count =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        applied = applied || header_mutation_count > 0;

        let content_type_guard_ready = https_response_body_content_type_guard_ready(&headers);
        let body_buffering_guard_ready = https_response_body_buffering_guard_ready(
            &message.body,
            outcome
                .body_mutation
                .as_ref()
                .map(|mutation| mutation.body.as_slice()),
        );
        if let Some(body_mutation) = &outcome.body_mutation {
            if content_type_guard_ready && body_buffering_guard_ready {
                applied = true;
                body_mutated = true;
                body_mutation_deferred = false;
                body = body_mutation.body.clone();
            }
        }
    }

    let content_type = plain_http_header_value(&headers, "Content-Type");
    let content_type_guard_ready = https_response_body_content_type_guard_ready(&headers);
    let body_buffering_guard_ready = https_response_body_buffering_guard_ready(
        &message.body,
        outcome
            .body_mutation
            .as_ref()
            .map(|mutation| mutation.body.as_slice()),
    );
    let script_dispatch_deferred = outcome.script_dispatch.is_some();
    if script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS response rewrite preview recorded script dispatch but JavaScript execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeHttpsResponseRewritePreviewReport {
        request_id: message.request_id.clone(),
        target_host: termination_plan.target_host.clone(),
        target_port: termination_plan.target_port,
        target_url: termination_plan.target_url.clone(),
        controlled_tls_termination_plan_ready: termination_plan
            .downstream_tls_termination_plan_ready,
        https_response_rewrite_preview_ready: true,
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        header_mutation_count,
        content_type,
        content_type_guard_ready,
        body_size_bytes: message.body.len(),
        body_size_limit_bytes: HTTP_PROXY_MAX_BODY_BYTES,
        body_buffering_guard_ready,
        body_mutated,
        body_mutation_deferred,
        https_request_rewrite_preview_ready: true,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        script_dispatch_deferred,
        headers,
        body,
        diagnostics,
    }
}
