//! The config document: profiles, listeners, nodes, routes and the entries
//! an import skips.

use super::*;

pub fn parse_config_document(raw_config: &str) -> DomainResult<ParsedConfigDocument> {
    let raw = toml::from_str::<RawConfigDocument>(raw_config).map_err(|_| {
        domain_error(
            CONFIG_PARSE_FAILED_CODE,
            "configuration could not be parsed as NetworkCore TOML",
        )
    })?;

    let schema_version = raw.schema_version.unwrap_or(CURRENT_SCHEMA_VERSION);
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(domain_error(
            CONFIG_SCHEMA_UNSUPPORTED_CODE,
            "configuration schema version is unsupported",
        ));
    }

    let profiles = collect_profiles(raw.profile, raw.profiles)?;
    let listeners = collect_listeners(raw.listeners.unwrap_or_default())?;
    let nodes = collect_nodes(raw.nodes.unwrap_or_default())?;
    let routes = collect_routes(raw.routes.unwrap_or_default())?;
    let routing = collect_routing(raw.rules, raw.policy_groups, &nodes)?;

    Ok(ParsedConfigDocument {
        schema_version: SchemaVersion::new(schema_version),
        profiles,
        listeners,
        nodes,
        routes,
        routing,
    })
}

pub(crate) fn collect_routing(
    rules: Option<Vec<String>>,
    policy_groups: Option<Vec<RawPolicyGroup>>,
    nodes: &[NodeDescriptor],
) -> DomainResult<Option<RoutingModel>> {
    if rules.is_none() && policy_groups.is_none() {
        return Ok(None);
    }
    let spec = RoutingSpec {
        rules: rules.unwrap_or_default(),
        groups: policy_groups
            .unwrap_or_default()
            .into_iter()
            .map(|group| PolicyGroupSpec {
                id: group.id,
                kind: group.kind,
                members: group.members,
                default: group.default,
                url: group.url,
                interval_secs: group.interval_secs,
                tolerance_ms: group.tolerance_ms,
                evaluate_before_use: group.evaluate_before_use.unwrap_or(false),
                network_rules: group
                    .network_rules
                    .unwrap_or_default()
                    .into_iter()
                    .map(|rule| NetworkRuleSpec {
                        when: rule.when,
                        target: rule.target,
                    })
                    .collect(),
            })
            .collect(),
    };
    let node_ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    RoutingModel::from_spec(&spec, &node_ids).map(Some)
}

pub(crate) fn collect_profiles(
    profile: Option<String>,
    profiles: Option<Vec<String>>,
) -> DomainResult<Vec<String>> {
    let profiles = match (profile, profiles) {
        (Some(_), Some(_)) => {
            return Err(domain_error(
                CONFIG_PROFILE_CONFLICT_CODE,
                "configuration must use either profile or profiles",
            ));
        }
        (Some(profile), None) => vec![profile],
        (None, Some(profiles)) => profiles,
        (None, None) => {
            return Err(domain_error(
                CONFIG_PROFILE_MISSING_CODE,
                "configuration must define at least one profile",
            ));
        }
    };

    if profiles.is_empty() {
        return Err(domain_error(
            CONFIG_PROFILE_MISSING_CODE,
            "configuration must define at least one profile",
        ));
    }

    let profiles = profiles
        .into_iter()
        .map(|profile| profile.trim().to_string())
        .collect::<Vec<_>>();

    if profiles.iter().any(String::is_empty) {
        return Err(domain_error(
            CONFIG_PROFILE_EMPTY_CODE,
            "configuration profiles cannot be empty",
        ));
    }

    Ok(profiles)
}

pub(crate) fn collect_listeners(
    raw_listeners: Vec<RawListener>,
) -> DomainResult<Vec<ListenerDescriptor>> {
    raw_listeners
        .into_iter()
        .map(normalize_listener)
        .collect::<DomainResult<Vec<_>>>()
}

pub(crate) fn normalize_listener(raw: RawListener) -> DomainResult<ListenerDescriptor> {
    let id = required_trimmed(
        raw.id,
        CONFIG_LISTENER_ID_EMPTY_CODE,
        "listener id cannot be empty",
    )?;
    let kind = parse_listener_kind(raw.kind)?;
    let bind_host = required_trimmed(
        raw.bind_host,
        CONFIG_LISTENER_BIND_HOST_EMPTY_CODE,
        "listener bind host cannot be empty",
    )?;
    let bind_port = parse_port(
        raw.bind_port,
        CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
        "listener bind port must be between 1 and 65535",
    )?;

    Ok(ListenerDescriptor {
        id,
        enabled: raw.enabled.unwrap_or(true),
        kind,
        bind: ListenerBind {
            host: bind_host,
            port: bind_port,
        },
        network: parse_listener_network(raw.network)?,
        route: parse_listener_route(raw.route, raw.route_action, raw.route_node)?,
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

pub(crate) fn parse_listener_kind(raw: String) -> DomainResult<ListenerKind> {
    let kind = required_trimmed(
        raw,
        CONFIG_LISTENER_KIND_EMPTY_CODE,
        "listener kind cannot be empty",
    )?;

    Ok(match normalized_token(&kind).as_str() {
        "local_tcp" => ListenerKind::LocalTcp,
        "socks" => ListenerKind::Socks,
        "http" => ListenerKind::Http,
        "tun" => ListenerKind::Tun,
        _ => ListenerKind::Other(kind),
    })
}

pub(crate) fn parse_listener_network(raw: String) -> DomainResult<ListenerNetwork> {
    match normalized_token(&raw).as_str() {
        "tcp" => Ok(ListenerNetwork::Tcp),
        "udp" => Ok(ListenerNetwork::Udp),
        "tcp_udp" => Ok(ListenerNetwork::TcpUdp),
        _ => Err(domain_error(
            CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE,
            "listener network must be tcp, udp, or tcp_udp",
        )),
    }
}

pub(crate) fn parse_listener_route(
    route: Option<String>,
    route_action: Option<String>,
    route_node: Option<String>,
) -> DomainResult<ListenerRoute> {
    match (route, route_action) {
        (Some(route), None) => Ok(ListenerRoute::RuleSet {
            rule_set_id: required_trimmed(
                route,
                CONFIG_LISTENER_ROUTE_MISSING_CODE,
                "listener route cannot be empty",
            )?,
        }),
        (None, Some(action)) => Ok(ListenerRoute::DefaultAction(parse_route_action(
            action, route_node,
        )?)),
        (Some(_), Some(_)) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_CONFLICT_CODE,
            "listener must use either route or route_action",
        )),
        (None, None) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_MISSING_CODE,
            "listener must define route or route_action",
        )),
    }
}

pub(crate) fn collect_nodes(raw_nodes: Vec<RawNode>) -> DomainResult<Vec<NodeDescriptor>> {
    raw_nodes
        .into_iter()
        .map(normalize_node)
        .collect::<DomainResult<Vec<_>>>()
}

pub(crate) fn normalize_node(raw: RawNode) -> DomainResult<NodeDescriptor> {
    let id = required_trimmed(raw.id, CONFIG_NODE_ID_EMPTY_CODE, "node id cannot be empty")?;
    let name = match raw.name {
        Some(name) => required_trimmed(
            name,
            CONFIG_NODE_NAME_EMPTY_CODE,
            "node name cannot be empty",
        )?,
        None => id.clone(),
    };
    let host = required_trimmed(
        raw.host,
        CONFIG_NODE_HOST_EMPTY_CODE,
        "node host cannot be empty",
    )?;
    let port = parse_port(
        raw.port,
        CONFIG_NODE_PORT_INVALID_CODE,
        "node port must be between 1 and 65535",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: parse_protocol(raw.protocol)?,
        endpoint: Endpoint { host, port },
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

/// Bad entries one subscription format left out, so the entries around them
/// still import. Each becomes a warning [`Diagnostic`] with the entry's own
/// error code; the first error is what [`SkippedEntries::finish`] returns
/// when no entry could be imported at all.
pub(crate) struct SkippedEntries {
    /// How the format calls one entry (`clash proxy`, `share link`, ...).
    pub(crate) entry: &'static str,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) first_error: Option<DomainError>,
}

/// Longest entry name a skip warning repeats.
pub(crate) const MAX_SKIPPED_ENTRY_NAME_CHARS: usize = 64;
/// Longest entry type a skip warning repeats.
pub(crate) const MAX_SKIPPED_ENTRY_KIND_LEN: usize = 32;

impl SkippedEntries {
    pub(crate) fn new(entry: &'static str) -> Self {
        Self {
            entry,
            diagnostics: Vec::new(),
            first_error: None,
        }
    }

    /// Records that entry `index` (counted from 0) was left out. The warning
    /// names the entry by its position, and by its declared name and type
    /// when they look like labels, with the error's fixed reason; never by
    /// the entry's text, which holds its credentials.
    pub(crate) fn skip(
        &mut self,
        index: usize,
        name: Option<&str>,
        kind: Option<&str>,
        error: DomainError,
    ) {
        let position = index + 1;
        let name = name.map(str::trim).filter(|name| is_entry_label(name));
        let kind = kind.map(str::trim).filter(|kind| is_entry_kind(kind));
        let entry = match (name, kind) {
            (Some(name), Some(kind)) => format!("{} {position} ({name}, type {kind})", self.entry),
            (Some(name), None) => format!("{} {position} ({name})", self.entry),
            (None, Some(kind)) => format!("{} {position} (type {kind})", self.entry),
            (None, None) => format!("{} {position}", self.entry),
        };
        self.diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            error.code.clone(),
            format!("{entry} was skipped: {}", error.message),
            Some(SOURCE_SUBSCRIPTION_CORE.to_string()),
        ));
        if self.first_error.is_none() {
            self.first_error = Some(error);
        }
    }

    /// The document of the imported `nodes` with a warning per skipped
    /// entry, or, when there are none, the first skipped entry's error
    /// (`none_imported` when no entry failed, as when every entry was a
    /// built-in policy).
    pub(crate) fn finish(
        self,
        nodes: Vec<NodeDescriptor>,
        none_imported: impl FnOnce() -> DomainError,
    ) -> DomainResult<SubscriptionDocument> {
        if nodes.is_empty() {
            return Err(self.first_error.unwrap_or_else(none_imported));
        }
        Ok(SubscriptionDocument {
            nodes,
            rules: Vec::new(),
            diagnostics: self.diagnostics,
        })
    }
}

/// Whether an entry's declared name can be repeated in a warning: short,
/// one line, and not shaped like a link or credentials.
pub(crate) fn is_entry_label(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_SKIPPED_ENTRY_NAME_CHARS
        && !name.contains("://")
        && !name.contains('@')
        && !name.chars().any(char::is_control)
}

/// Whether an entry's type can be repeated in a warning: one short word.
pub(crate) fn is_entry_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_SKIPPED_ENTRY_KIND_LEN
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn collect_routes(raw_routes: Vec<RawRoute>) -> DomainResult<Vec<RuleSet>> {
    raw_routes
        .into_iter()
        .map(normalize_route)
        .collect::<DomainResult<Vec<_>>>()
}

pub(crate) fn normalize_route(raw: RawRoute) -> DomainResult<RuleSet> {
    Ok(RuleSet {
        id: required_trimmed(
            raw.id,
            CONFIG_ROUTE_ID_EMPTY_CODE,
            "route id cannot be empty",
        )?,
        rules: Vec::new(),
        default_action: parse_route_action(raw.default_action, raw.default_node)?,
    })
}

pub(crate) fn parse_route_action(
    raw_action: String,
    node_id: Option<String>,
) -> DomainResult<RouteAction> {
    match normalized_token(&raw_action).as_str() {
        "direct" => Ok(RouteAction::Direct),
        "reject" => Ok(RouteAction::Reject),
        "proxy" => Ok(RouteAction::Proxy {
            node_id: required_trimmed(
                node_id.unwrap_or_default(),
                CONFIG_ROUTE_PROXY_NODE_MISSING_CODE,
                "proxy route action requires a node id",
            )?,
        }),
        _ => Err(domain_error(
            CONFIG_ROUTE_ACTION_UNSUPPORTED_CODE,
            "route action must be direct, proxy, or reject",
        )),
    }
}

pub(crate) fn collect_tags(tags: Option<Vec<String>>) -> Vec<String> {
    tags.unwrap_or_default()
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

pub(crate) fn collect_metadata(metadata: Option<BTreeMap<String, String>>) -> Metadata {
    metadata
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| MetadataEntry {
            key: key.trim().to_string(),
            value,
        })
        .filter(|entry| !entry.key.is_empty())
        .collect()
}

pub(crate) fn parse_port(
    value: i64,
    code: &'static str,
    message: impl Into<String>,
) -> DomainResult<u16> {
    if !(1..=(u16::MAX as i64)).contains(&value) {
        return Err(domain_error(code, message));
    }

    Ok(value as u16)
}

pub(crate) fn required_trimmed(
    value: String,
    code: &'static str,
    message: impl Into<String>,
) -> DomainResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(domain_error(code, message))
    } else {
        Ok(value)
    }
}

pub(crate) fn normalized_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}
