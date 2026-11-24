//! SOCKS5: the client handshake and the outbound CONNECT exchange.

use super::*;

pub fn read_socks5_greeting<R>(reader: &mut R) -> NativeSocks5GreetingReadReport
where
    R: Read,
{
    let mut header = [0_u8; 2];
    if reader.read_exact(&mut header).is_err() {
        return NativeSocks5GreetingReadReport {
            greeting: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
                "native SOCKS5 greeting header could not be read",
            )],
        };
    }

    let version = header[0];
    let method_count = header[1] as usize;

    if version != SOCKS5_VERSION {
        return NativeSocks5GreetingReadReport {
            greeting: Some(NativeSocks5Greeting {
                version,
                auth_methods: Vec::new(),
            }),
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
                "native SOCKS5 greeting version is unsupported",
            )],
        };
    }

    if method_count == 0 {
        return NativeSocks5GreetingReadReport {
            greeting: Some(NativeSocks5Greeting {
                version,
                auth_methods: Vec::new(),
            }),
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
                "native SOCKS5 greeting must advertise at least one auth method",
            )],
        };
    }

    let mut auth_methods = vec![0_u8; method_count];
    if reader.read_exact(&mut auth_methods).is_err() {
        return NativeSocks5GreetingReadReport {
            greeting: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
                "native SOCKS5 greeting auth methods could not be read",
            )],
        };
    }

    NativeSocks5GreetingReadReport {
        greeting: Some(NativeSocks5Greeting {
            version,
            auth_methods,
        }),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
            "native SOCKS5 greeting version and auth methods were read",
        )],
    }
}

pub fn select_socks5_auth_method(
    greeting: &NativeSocks5Greeting,
) -> NativeSocks5AuthMethodSelectionReport {
    if greeting.version == SOCKS5_VERSION
        && greeting
            .auth_methods
            .contains(&SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED)
    {
        return NativeSocks5AuthMethodSelectionReport {
            decision: NativeSocks5AuthMethodDecision::NoAuthenticationRequired,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
                "native SOCKS5 no-auth method was selected",
            )],
        };
    }

    NativeSocks5AuthMethodSelectionReport {
        decision: NativeSocks5AuthMethodDecision::NoAcceptableMethods,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE,
            "native SOCKS5 greeting does not advertise a supported auth method",
        )],
    }
}

pub fn write_socks5_auth_method_response<W>(
    writer: &mut W,
    decision: NativeSocks5AuthMethodDecision,
) -> NativeSocks5AuthMethodResponseWriteReport
where
    W: Write,
{
    let response = [SOCKS5_VERSION, decision.method_code()];
    let diagnostic = if writer.write_all(&response).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 auth method response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 auth method response could not be written",
        )
    };

    NativeSocks5AuthMethodResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_socks5_command_header<R>(reader: &mut R) -> NativeSocks5CommandHeaderReadReport
where
    R: Read,
{
    let mut header = [0_u8; 4];
    if reader.read_exact(&mut header).is_err() {
        return NativeSocks5CommandHeaderReadReport {
            command_header: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE,
                "native SOCKS5 command header could not be read",
            )],
        };
    }

    let command_header = NativeSocks5CommandHeader {
        version: header[0],
        command: header[1],
        reserved: header[2],
        address_type: header[3],
    };
    let diagnostic = if socks5_command_header_valid(&command_header) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
            "native SOCKS5 command header was read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE,
            "native SOCKS5 command header is invalid",
        )
    };

    NativeSocks5CommandHeaderReadReport {
        command_header: Some(command_header),
        diagnostics: vec![diagnostic],
    }
}

pub fn reject_unsupported_socks5_command(
    command_header: &NativeSocks5CommandHeader,
) -> NativeSocks5CommandSupportReport {
    if command_header.command == SOCKS5_COMMAND_CONNECT {
        return NativeSocks5CommandSupportReport {
            decision: NativeSocks5CommandDecision::Connect,
            diagnostics: Vec::new(),
        };
    }

    NativeSocks5CommandSupportReport {
        decision: NativeSocks5CommandDecision::UnsupportedCommand,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
            "native SOCKS5 command is not supported",
        )],
    }
}

pub fn read_socks5_connect_target<R>(
    reader: &mut R,
    command_header: &NativeSocks5CommandHeader,
) -> NativeSocks5ConnectTargetReadReport
where
    R: Read,
{
    if !socks5_command_header_valid(command_header)
        || command_header.command != SOCKS5_COMMAND_CONNECT
    {
        return NativeSocks5ConnectTargetReadReport {
            target: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                "native SOCKS5 CONNECT target requires a valid CONNECT command header",
            )],
        };
    }

    let address = match command_header.address_type {
        SOCKS5_ADDRESS_TYPE_IPV4 => {
            let mut address = [0_u8; 4];
            if reader.read_exact(&mut address).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT IPv4 target address could not be read",
                );
            }
            NativeSocks5Address::Ipv4(address)
        }
        SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
            let mut length = [0_u8; 1];
            if reader.read_exact(&mut length).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT domain length could not be read",
                );
            }
            if length[0] == 0 {
                return NativeSocks5ConnectTargetReadReport {
                    target: None,
                    diagnostics: vec![runtime_warning(
                        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                        "native SOCKS5 CONNECT domain target cannot be empty",
                    )],
                };
            }

            let mut domain_name = vec![0_u8; length[0] as usize];
            if reader.read_exact(&mut domain_name).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT domain target could not be read",
                );
            }

            match String::from_utf8(domain_name) {
                Ok(domain_name) => NativeSocks5Address::DomainName(domain_name),
                Err(_) => {
                    return NativeSocks5ConnectTargetReadReport {
                        target: None,
                        diagnostics: vec![runtime_warning(
                            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                            "native SOCKS5 CONNECT domain target must be valid UTF-8",
                        )],
                    };
                }
            }
        }
        SOCKS5_ADDRESS_TYPE_IPV6 => {
            let mut address = [0_u8; 16];
            if reader.read_exact(&mut address).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT IPv6 target address could not be read",
                );
            }
            NativeSocks5Address::Ipv6(address)
        }
        _ => {
            return NativeSocks5ConnectTargetReadReport {
                target: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                    "native SOCKS5 CONNECT target address type is unsupported",
                )],
            };
        }
    };

    let mut port = [0_u8; 2];
    if reader.read_exact(&mut port).is_err() {
        return socks5_connect_target_read_failed(
            "native SOCKS5 CONNECT target port could not be read",
        );
    }

    let target = NativeSocks5ConnectTarget {
        address,
        port: u16::from_be_bytes(port),
    };
    let diagnostic = if socks5_connect_target_valid(&target) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
            "native SOCKS5 CONNECT target address and port were read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
            "native SOCKS5 CONNECT target address or port is invalid",
        )
    };

    NativeSocks5ConnectTargetReadReport {
        target: Some(target),
        diagnostics: vec![diagnostic],
    }
}

pub fn reject_unwired_socks5_route_outbound(
    _target: &NativeSocks5ConnectTarget,
) -> NativeSocks5RouteOutboundReport {
    NativeSocks5RouteOutboundReport {
        decision: NativeSocks5RouteOutboundDecision::Unwired,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
            "native SOCKS5 CONNECT route and outbound data plane are not wired",
        )],
    }
}

pub fn select_socks5_route_outbound_behavior(
    target: &NativeSocks5ConnectTarget,
    outbound_handler: &NativeOutboundHandlerHandle,
) -> NativeSocks5RouteOutboundSelectionReport {
    NativeSocks5RouteOutboundSelectionReport {
        behavior: NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
            target: target.clone(),
            outbound_handler: outbound_handler.clone(),
        },
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
            "native SOCKS5 CONNECT route selected the configured outbound handler",
        )],
    }
}

pub fn build_socks5_outbound_connect_request_frame(
    behavior: &NativeSocks5RouteOutboundBehavior,
) -> NativeSocks5OutboundConnectRequestFrameReport {
    let NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound { target, .. } = behavior;

    if let Some(frame) = socks5_outbound_connect_request_frame_bytes(target) {
        return NativeSocks5OutboundConnectRequestFrameReport {
            frame,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
                "native SOCKS5 outbound CONNECT request frame was generated",
            )],
        };
    }

    NativeSocks5OutboundConnectRequestFrameReport {
        frame: Vec::new(),
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE,
            "native SOCKS5 outbound CONNECT request frame target is invalid",
        )],
    }
}

pub fn plan_socks5_outbound_tcp_connection(
    behavior: &NativeSocks5RouteOutboundBehavior,
    request_frame: &[u8],
) -> NativeSocks5OutboundTcpConnectionPlanReport {
    let NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target,
        outbound_handler,
    } = behavior;

    if outbound_handler.protocol != Protocol::Socks
        || outbound_handler.endpoint.host.trim().is_empty()
        || outbound_handler.endpoint.port == 0
        || request_frame.is_empty()
    {
        return NativeSocks5OutboundTcpConnectionPlanReport {
            plan: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE,
                "native SOCKS5 outbound TCP connection plan is invalid",
            )],
        };
    }

    NativeSocks5OutboundTcpConnectionPlanReport {
        plan: Some(NativeSocks5OutboundTcpConnectionPlan {
            outbound_handler_id: outbound_handler.node_id.clone(),
            outbound_endpoint: outbound_handler.endpoint.clone(),
            target: target.clone(),
            request_frame: request_frame.to_vec(),
        }),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
            "native SOCKS5 outbound TCP connection plan was created",
        )],
    }
}

pub fn attempt_socks5_outbound_tcp_connection(
    plan: &NativeSocks5OutboundTcpConnectionPlan,
) -> NativeSocks5OutboundTcpConnectionAttemptReport {
    let Some(socket_addr) = endpoint_socket_addr(&plan.outbound_endpoint) else {
        return NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
                "native SOCKS5 outbound TCP connection attempt requires an IP endpoint",
            )],
        };
    };

    match TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_millis(OUTBOUND_CONNECTION_ATTEMPT_TIMEOUT_MS),
    ) {
        Ok(stream) => NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: Some(stream),
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE,
                "native SOCKS5 outbound TCP connection attempt succeeded",
            )],
        },
        Err(_) => NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
                "native SOCKS5 outbound TCP connection attempt failed",
            )],
        },
    }
}

pub fn write_socks5_outbound_connect_request<W>(
    writer: &mut W,
    plan: &NativeSocks5OutboundTcpConnectionPlan,
) -> NativeSocks5OutboundConnectRequestWriteReport
where
    W: Write,
{
    let request_frame = plan.request_frame.clone();
    let diagnostic = if request_frame.is_empty() {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT request requires a non-empty frame",
        )
    } else if writer.write_all(&request_frame).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            "native SOCKS5 outbound CONNECT request was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT request could not be written",
        )
    };

    NativeSocks5OutboundConnectRequestWriteReport {
        request_frame,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_socks5_outbound_connect_response<R>(
    reader: &mut R,
) -> NativeSocks5OutboundConnectResponseReadReport
where
    R: Read,
{
    let mut header = [0_u8; 4];
    if reader.read_exact(&mut header).is_err() {
        return socks5_outbound_connect_response_read_failed(
            "native SOCKS5 outbound CONNECT response header could not be read",
        );
    }

    let version = header[0];
    let reply = header[1];
    let reserved = header[2];
    let address_type = header[3];
    let bound_address = match address_type {
        SOCKS5_ADDRESS_TYPE_IPV4 => {
            let mut address = [0_u8; 4];
            if reader.read_exact(&mut address).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response IPv4 bound address could not be read",
                );
            }
            NativeSocks5Address::Ipv4(address)
        }
        SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
            let mut length = [0_u8; 1];
            if reader.read_exact(&mut length).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response domain length could not be read",
                );
            }
            if length[0] == 0 {
                return NativeSocks5OutboundConnectResponseReadReport {
                    response: None,
                    diagnostics: vec![runtime_warning(
                        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                        "native SOCKS5 outbound CONNECT response domain bound address cannot be empty",
                    )],
                };
            }

            let mut domain_name = vec![0_u8; length[0] as usize];
            if reader.read_exact(&mut domain_name).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response domain bound address could not be read",
                );
            }

            match String::from_utf8(domain_name) {
                Ok(domain_name) => NativeSocks5Address::DomainName(domain_name),
                Err(_) => {
                    return NativeSocks5OutboundConnectResponseReadReport {
                        response: None,
                        diagnostics: vec![runtime_warning(
                            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                            "native SOCKS5 outbound CONNECT response domain bound address must be valid UTF-8",
                        )],
                    };
                }
            }
        }
        SOCKS5_ADDRESS_TYPE_IPV6 => {
            let mut address = [0_u8; 16];
            if reader.read_exact(&mut address).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response IPv6 bound address could not be read",
                );
            }
            NativeSocks5Address::Ipv6(address)
        }
        _ => {
            return NativeSocks5OutboundConnectResponseReadReport {
                response: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                    "native SOCKS5 outbound CONNECT response address type is unsupported",
                )],
            };
        }
    };

    let mut bound_port = [0_u8; 2];
    if reader.read_exact(&mut bound_port).is_err() {
        return socks5_outbound_connect_response_read_failed(
            "native SOCKS5 outbound CONNECT response bound port could not be read",
        );
    }

    let response = NativeSocks5OutboundConnectResponse {
        version,
        reply,
        reserved,
        address_type,
        bound_address,
        bound_port: u16::from_be_bytes(bound_port),
    };
    let diagnostic = if socks5_outbound_connect_response_valid(&response) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE,
            "native SOCKS5 outbound CONNECT response was read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
            "native SOCKS5 outbound CONNECT response is invalid or not successful",
        )
    };

    NativeSocks5OutboundConnectResponseReadReport {
        response: Some(response),
        diagnostics: vec![diagnostic],
    }
}

pub fn decide_socks5_outbound_connect_response(
    response: &NativeSocks5OutboundConnectResponse,
) -> NativeSocks5OutboundConnectResponseDecisionReport {
    if socks5_outbound_connect_response_valid(response) {
        return NativeSocks5OutboundConnectResponseDecisionReport {
            decision: NativeSocks5OutboundConnectResponseDecision::Accepted,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE,
                "native SOCKS5 outbound CONNECT response accepted the upstream request",
            )],
        };
    }

    NativeSocks5OutboundConnectResponseDecisionReport {
        decision: NativeSocks5OutboundConnectResponseDecision::Rejected,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE,
            "native SOCKS5 outbound CONNECT response rejected the upstream request or is invalid",
        )],
    }
}

pub fn assess_socks5_outbound_connect_relay_readiness(
    decision: NativeSocks5OutboundConnectResponseDecision,
) -> NativeSocks5OutboundConnectRelayReadinessReport {
    match decision {
        NativeSocks5OutboundConnectResponseDecision::Accepted => {
            NativeSocks5OutboundConnectRelayReadinessReport {
                readiness: NativeSocks5OutboundConnectRelayReadiness::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE,
                    "native SOCKS5 outbound CONNECT relay is ready after upstream acceptance",
                )],
            }
        }
        NativeSocks5OutboundConnectResponseDecision::Rejected => {
            NativeSocks5OutboundConnectRelayReadinessReport {
                readiness: NativeSocks5OutboundConnectRelayReadiness::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT relay is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn plan_socks5_outbound_connect_data_relay(
    readiness: NativeSocks5OutboundConnectRelayReadiness,
) -> NativeSocks5OutboundConnectDataRelayPlanReport {
    match readiness {
        NativeSocks5OutboundConnectRelayReadiness::Ready => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectRelayReadiness::Blocked => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is not wired after upstream acceptance",
                )],
            }
        }
        NativeSocks5OutboundConnectRelayReadiness::Rejected => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn relay_socks5_outbound_connect_data<CR, OW, OR, CW>(
    client_reader: &mut CR,
    outbound_writer: &mut OW,
    outbound_reader: &mut OR,
    client_writer: &mut CW,
) -> NativeSocks5OutboundConnectDataRelayReport
where
    CR: Read,
    OW: Write,
    OR: Read,
    CW: Write,
{
    let client_to_outbound_result =
        relay_socks5_outbound_connect_data_direction(client_reader, outbound_writer);
    let outbound_to_client_result =
        relay_socks5_outbound_connect_data_direction(outbound_reader, client_writer);
    let client_to_outbound_bytes = client_to_outbound_result.as_ref().copied().unwrap_or(0);
    let outbound_to_client_bytes = outbound_to_client_result.as_ref().copied().unwrap_or(0);

    let diagnostic = if client_to_outbound_result.is_ok() && outbound_to_client_result.is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
            "native SOCKS5 outbound CONNECT data relay completed for both directions",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
            "native SOCKS5 outbound CONNECT data relay failed in at least one direction",
        )
    };

    NativeSocks5OutboundConnectDataRelayReport {
        client_to_outbound_bytes,
        outbound_to_client_bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn assess_socks5_outbound_connect_client_success_response_readiness(
    data_relay_plan: NativeSocks5OutboundConnectDataRelayPlanDecision,
) -> NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
    match data_relay_plan {
        NativeSocks5OutboundConnectDataRelayPlanDecision::Ready => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE,
                    "native SOCKS5 outbound CONNECT client success response is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT client success response is not ready because data relay is not wired",
                )],
            }
        }
        NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT client success response is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn plan_socks5_outbound_connect_client_success_response_write(
    readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness,
) -> NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
    match readiness {
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision: NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision:
                    NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is not wired",
                )],
            }
        }
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision:
                    NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn write_socks5_outbound_connect_client_success_response<W>(
    writer: &mut W,
    response: &NativeSocks5OutboundConnectResponse,
) -> NativeSocks5OutboundConnectClientSuccessResponseWriteReport
where
    W: Write,
{
    let response_frame =
        socks5_outbound_connect_client_success_response_frame(response).unwrap_or_default();
    let diagnostic = if response_frame.is_empty() {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT client success response requires a valid upstream success response",
        )
    } else if writer.write_all(&response_frame).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 outbound CONNECT client success response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT client success response could not be written",
        )
    };

    NativeSocks5OutboundConnectClientSuccessResponseWriteReport {
        response_frame,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_unwired_socks5_connect_failure_response<W>(
    writer: &mut W,
) -> NativeSocks5ConnectFailureResponseWriteReport
where
    W: Write,
{
    let response = SOCKS5_CONNECT_FAILURE_RESPONSE;
    let diagnostic = if writer.write_all(&response).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 CONNECT failure response was written for unwired route and outbound handling",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 CONNECT failure response could not be written",
        )
    };

    NativeSocks5ConnectFailureResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}
