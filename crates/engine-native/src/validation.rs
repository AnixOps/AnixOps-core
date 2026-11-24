//! Config validation: listeners, nodes, routes and supported protocols.

use super::*;

pub(crate) fn validate_listeners(
    engine_config: &ProxyEngineConfig,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let listeners = &engine_config.config.listeners;
    let enabled_listeners = enabled_listeners(listeners);

    if enabled_listeners.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
            "native proxy engine requires at least one enabled listener",
        ));
    }

    if has_duplicate_ids(listeners.iter().map(|listener| listener.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
            "native proxy listener ids must be unique",
        ));
    }

    if enabled_listeners
        .iter()
        .any(|listener| listener.bind.host.trim().is_empty() || listener.bind.port == 0)
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
            "native proxy listener bind host and port must be explicit",
        ));
    }

    if enabled_listeners
        .iter()
        .any(|listener| !listener_kind_supported(&listener.kind))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
            "native proxy listener handlers are not implemented yet",
        ));
    }
}

pub(crate) fn validate_nodes(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let nodes = effective_nodes(engine_config);

    if nodes.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE,
            "native proxy engine requires at least one typed outbound node",
        ));
    }

    if has_duplicate_ids(nodes.iter().map(|node| node.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE,
            "native proxy node ids must be unique across config and runtime request nodes",
        ));
    }

    if nodes
        .iter()
        .any(|node| !node_protocol_supported(&node.protocol))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
            "native proxy outbound protocols are not implemented yet",
        ));
    }
}

pub(crate) fn validate_routes(
    engine_config: &ProxyEngineConfig,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let route_sets = &engine_config.config.policies;
    let enabled_listeners = enabled_listeners(&engine_config.config.listeners);
    let node_ids = effective_node_ids(engine_config);
    let mut target_missing = false;
    let mut has_executable_proxy_route = false;

    if has_duplicate_ids(route_sets.iter().map(|route_set| route_set.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE,
            "native proxy route ids must be unique",
        ));
    }

    for listener in &enabled_listeners {
        match &listener.route {
            ListenerRoute::RuleSet { rule_set_id } => {
                let Some(route_set) = route_sets
                    .iter()
                    .find(|route_set| route_set.id == *rule_set_id)
                else {
                    target_missing = true;
                    continue;
                };
                let route_result = validate_route_set(route_set, &node_ids);
                target_missing |= route_result.target_missing;
                has_executable_proxy_route |= route_result.has_executable_proxy_route;
            }
            ListenerRoute::DefaultAction(action) => {
                let action_result = validate_route_action(action, &node_ids);
                target_missing |= action_result.target_missing;
                has_executable_proxy_route |= action_result.has_executable_proxy_route;
            }
        }
    }

    for route_set in route_sets {
        for rule in &route_set.rules {
            target_missing |= validate_route_action(&rule.action, &node_ids).target_missing;
        }
        target_missing |=
            validate_route_action(&route_set.default_action, &node_ids).target_missing;
    }

    if target_missing {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
            "native proxy routes must reference existing rule sets and nodes",
        ));
    }

    if !enabled_listeners.is_empty() && !has_executable_proxy_route {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE,
            "native proxy listeners must have at least one proxy route to a typed node",
        ));
    }
}

pub(crate) fn ensure_native_engine_id(engine_id: &str) -> DomainResult<()> {
    if engine_id == DEFAULT_NATIVE_ENGINE_ID {
        return Ok(());
    }

    Err(domain_error(
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
        "native proxy engine only supports the native engine id",
    ))
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RouteValidation {
    pub(crate) target_missing: bool,
    pub(crate) has_executable_proxy_route: bool,
}

pub(crate) fn validate_route_set(
    route_set: &RuleSet,
    node_ids: &BTreeSet<String>,
) -> RouteValidation {
    let mut validation = RouteValidation::default();

    for rule in &route_set.rules {
        validation = validation.combine(validate_route_action(&rule.action, node_ids));
    }

    validation.combine(validate_route_action(&route_set.default_action, node_ids))
}

pub(crate) fn validate_route_action(
    action: &RouteAction,
    node_ids: &BTreeSet<String>,
) -> RouteValidation {
    match action {
        RouteAction::Proxy { node_id } if node_ids.contains(node_id) => RouteValidation {
            target_missing: false,
            has_executable_proxy_route: true,
        },
        RouteAction::Proxy { .. } => RouteValidation {
            target_missing: true,
            has_executable_proxy_route: false,
        },
        RouteAction::Direct | RouteAction::Reject => RouteValidation::default(),
    }
}

impl RouteValidation {
    pub(crate) fn combine(self, other: Self) -> Self {
        Self {
            target_missing: self.target_missing || other.target_missing,
            has_executable_proxy_route: self.has_executable_proxy_route
                || other.has_executable_proxy_route,
        }
    }
}

pub(crate) fn enabled_listeners(listeners: &[ListenerDescriptor]) -> Vec<&ListenerDescriptor> {
    listeners
        .iter()
        .filter(|listener| listener.enabled)
        .collect()
}

pub(crate) fn effective_nodes(engine_config: &ProxyEngineConfig) -> Vec<&NodeDescriptor> {
    engine_config
        .config
        .nodes
        .iter()
        .chain(engine_config.nodes.iter())
        .collect()
}

pub(crate) fn ensure_native_config_has_no_errors(
    engine_config: &ProxyEngineConfig,
) -> DomainResult<()> {
    let service = NativeProxyEngineService::new();
    if let Some(diagnostic) = service
        .validate_config(engine_config)
        .into_iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(domain_error(diagnostic.code, diagnostic.message));
    }

    Ok(())
}

pub(crate) fn select_runtime_node<'a>(
    engine_config: &'a ProxyEngineConfig,
    listener: &ListenerDescriptor,
) -> DomainResult<&'a NodeDescriptor> {
    let node_id = select_runtime_proxy_node_id(&listener.route, &engine_config.config.policies)?;
    effective_nodes(engine_config)
        .into_iter()
        .find(|node| node.id == node_id)
        .ok_or_else(|| {
            runtime_error(
                ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
                "native runtime assembly plan route must reference an existing node",
            )
        })
}

pub(crate) fn select_runtime_proxy_node_id<'a>(
    route: &'a ListenerRoute,
    route_sets: &'a [RuleSet],
) -> DomainResult<&'a str> {
    let node_id = match route {
        ListenerRoute::DefaultAction(action) => proxy_node_id(action),
        ListenerRoute::RuleSet { rule_set_id } => {
            let route_set = route_sets
                .iter()
                .find(|route_set| route_set.id == *rule_set_id)
                .ok_or_else(|| {
                    runtime_error(
                        ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
                        "native runtime assembly plan route set must exist",
                    )
                })?;
            route_set
                .rules
                .iter()
                .find_map(|rule| proxy_node_id(&rule.action))
                .or_else(|| proxy_node_id(&route_set.default_action))
        }
    };

    node_id.ok_or_else(|| {
        runtime_error(
            ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
            "native runtime assembly plan requires a proxy route to a socks outbound node",
        )
    })
}

pub(crate) fn proxy_node_id(action: &RouteAction) -> Option<&str> {
    match action {
        RouteAction::Proxy { node_id } => Some(node_id),
        RouteAction::Direct | RouteAction::Reject => None,
    }
}

pub(crate) fn effective_node_ids(engine_config: &ProxyEngineConfig) -> BTreeSet<String> {
    effective_nodes(engine_config)
        .into_iter()
        .map(|node| node.id.clone())
        .collect()
}

pub(crate) fn has_duplicate_ids<'a>(mut ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    ids.any(|id| !seen.insert(id))
}

pub(crate) fn listener_kind_supported(kind: &ListenerKind) -> bool {
    listener_runtime_kind_supported(kind)
}

pub(crate) fn node_protocol_supported(protocol: &Protocol) -> bool {
    outbound_runtime_protocol_supported(protocol)
}

pub(crate) fn listener_runtime_kind_supported(kind: &ListenerKind) -> bool {
    matches!(
        kind,
        ListenerKind::LocalTcp | ListenerKind::Socks | ListenerKind::Http
    )
}

pub(crate) fn outbound_runtime_protocol_supported(protocol: &Protocol) -> bool {
    matches!(protocol, Protocol::Socks)
}
