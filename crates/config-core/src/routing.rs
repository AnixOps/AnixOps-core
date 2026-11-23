//! First-class routing rules and policy groups.
//!
//! This module owns the platform-neutral routing model: ordered
//! DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/IP-CIDR/GEOIP/GEOSITE/DST-PORT/
//! SRC-IP/SRC-PORT/IN-PORT/PROCESS-NAME/HOSTNAME-TYPE/SUBNET/DEVICE-NAME/
//! CELLULAR-RADIO/RULE-SET/SCRIPT rules and AND/OR/NOT combinations of them, a
//! mandatory FINAL target (optionally `dns-failed` or `dns-continue`), and
//! select/url-test/fallback policy groups. In-process engines call
//! [`RoutingModel::decide`] directly, and snapshot tests pin its results. The module performs no DNS, GeoIP database, health check,
//! or network work; those inputs come from a [`RoutingEnvironment`].

use control_domain::{DomainError, DomainResult};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ROUTING_RULE_LINE_INVALID_CODE: &str = "config.core.routing_rule_line_invalid";
pub const ROUTING_RULE_TYPE_UNSUPPORTED_CODE: &str = "config.core.routing_rule_type_unsupported";
pub const ROUTING_RULE_VALUE_INVALID_CODE: &str = "config.core.routing_rule_value_invalid";
pub const ROUTING_RULE_OPTION_UNSUPPORTED_CODE: &str =
    "config.core.routing_rule_option_unsupported";
pub const ROUTING_TARGET_UNKNOWN_CODE: &str = "config.core.routing_target_unknown";
pub const ROUTING_FINAL_MISSING_CODE: &str = "config.core.routing_final_missing";
pub const ROUTING_FINAL_NOT_LAST_CODE: &str = "config.core.routing_final_not_last";
pub const ROUTING_GROUP_ID_INVALID_CODE: &str = "config.core.routing_group_id_invalid";
pub const ROUTING_GROUP_ID_CONFLICT_CODE: &str = "config.core.routing_group_id_conflict";
pub const ROUTING_GROUP_TYPE_UNSUPPORTED_CODE: &str = "config.core.routing_group_type_unsupported";
pub const ROUTING_GROUP_MEMBERS_EMPTY_CODE: &str = "config.core.routing_group_members_empty";
pub const ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE: &str =
    "config.core.routing_group_member_unsupported";
pub const ROUTING_GROUP_DEFAULT_INVALID_CODE: &str = "config.core.routing_group_default_invalid";
pub const ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE: &str =
    "config.core.routing_group_health_check_invalid";
pub const ROUTING_GROUP_CYCLE_CODE: &str = "config.core.routing_group_cycle";
pub const ROUTING_GROUP_NETWORK_RULE_INVALID_CODE: &str =
    "config.core.routing_group_network_rule_invalid";

pub const DEFAULT_HEALTH_CHECK_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u32 = 300;
pub const DEFAULT_URL_TEST_TOLERANCE_MS: u16 = 50;

const RESERVED_DIRECT: &str = "DIRECT";
const RESERVED_NAMES: [&str; 2] = [RESERVED_DIRECT, "FINAL"];

/// How a REJECT policy answers, as Surge's REJECT family.
///
/// A plain [`RejectKind::Reject`] closes the connection; when one host is
/// rejected more than ten times in thirty seconds the engine answers it
/// like [`RejectKind::Drop`] until the retries calm down, so an app that
/// retries at once does not spin. [`RejectKind::NoDrop`] never does that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RejectKind {
    /// `REJECT`: close the connection.
    #[default]
    Reject,
    /// `REJECT-NO-DROP`: close the connection, never upgraded to a drop.
    NoDrop,
    /// `REJECT-DROP`: answer nothing, so the client waits for its own
    /// timeout instead of retrying at once.
    Drop,
    /// `REJECT-TINYGIF` (Loon `REJECT-IMG`): answer a plain HTTP request
    /// with a 1x1 GIF; any other flow is closed as with `REJECT`.
    TinyGif,
}

impl RejectKind {
    pub const ALL: [Self; 4] = [Self::Reject, Self::NoDrop, Self::Drop, Self::TinyGif];

    /// The policy name: `REJECT`, `REJECT-NO-DROP`, `REJECT-DROP` or
    /// `REJECT-TINYGIF`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Reject => "REJECT",
            Self::NoDrop => "REJECT-NO-DROP",
            Self::Drop => "REJECT-DROP",
            Self::TinyGif => "REJECT-TINYGIF",
        }
    }

    /// The kind a policy name stands for, ignoring case; Loon's
    /// `REJECT-IMG` is `REJECT-TINYGIF`. Other `REJECT-` names are `None`.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("REJECT-IMG") {
            return Some(Self::TinyGif);
        }
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(name))
    }
}

/// `REJECT` and Surge's `REJECT-*` variants.
fn is_reject_target(target: &str) -> bool {
    let target = target.trim().to_ascii_uppercase();
    target == "REJECT" || target.starts_with("REJECT-")
}

/// Unvalidated routing input: Loon-style rule lines and policy group specs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingSpec {
    pub rules: Vec<String>,
    pub groups: Vec<PolicyGroupSpec>,
}

/// Unvalidated policy group input. Targets are referenced by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyGroupSpec {
    pub id: String,
    pub kind: String,
    /// Empty for a subnet group, which takes its members from
    /// `network_rules` and `default`.
    pub members: Vec<String>,
    /// Initial member of a select group; the target of a subnet group when
    /// no network rule matches.
    pub default: Option<String>,
    pub url: Option<String>,
    pub interval_secs: Option<u32>,
    pub tolerance_ms: Option<u16>,
    /// Health-checked groups only: a connection through the group waits for
    /// a check when the group has no result yet (first use, or after the
    /// network changed) instead of taking the first member.
    pub evaluate_before_use: bool,
    /// Subnet groups only, tried in order.
    pub network_rules: Vec<NetworkRuleSpec>,
}

/// One rule of a subnet group: `when` the device's network matches, use
/// `target`. `when` is `SSID:<name>`, `BSSID:<mac>`, `ROUTER:<ip>`,
/// `SUBNET:<cidr>` (an address of the device), `TYPE:WIFI`, `TYPE:WIRED`,
/// `TYPE:CELLULAR`, or `CELLULAR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRuleSpec {
    pub when: String,
    pub target: String,
}

/// Where a rule, FINAL, or group member sends a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyTarget {
    Direct,
    Reject(RejectKind),
    Node(String),
    Group(String),
}

impl PolicyTarget {
    /// Returns the configuration name used to reference this target.
    pub fn name(&self) -> &str {
        match self {
            Self::Direct => RESERVED_DIRECT,
            Self::Reject(kind) => kind.name(),
            Self::Node(id) | Self::Group(id) => id,
        }
    }
}

/// IPv4 or IPv6 network in CIDR notation, normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.trim().split_once('/')?;
        let address = address.trim().parse::<IpAddr>().ok()?;
        let prefix_len = prefix.trim().parse::<u8>().ok()?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return None;
        }
        Some(Self {
            network: mask_ip(address, prefix_len),
            prefix_len,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network.is_ipv4() == ip.is_ipv4() && mask_ip(ip, self.prefix_len) == self.network
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

fn mask_ip(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

/// Values of a `PROTOCOL` rule. `QUIC` is UDP to port 443, `HTTPS` TCP to
/// port 443 and `HTTP` TCP to port 80, as far as routing can tell before
/// the first bytes. `STUN` is UDP to a STUN/TURN port (3478, 3479, 5349 and
/// 19302-19309). Following the common rule syntax, `DOH` and `DOQ` match the engine's own
/// DNS-over-HTTPS and DNS-over-QUIC queries to a proxied server
/// ([`RouteQuery::dns`]), so a rule can pick the proxy they go through;
/// an app's connections never match them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Quic,
    Http,
    Https,
    Stun,
    Doh,
    Doq,
}

impl RuleProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Quic => "QUIC",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Stun => "STUN",
            Self::Doh => "DOH",
            Self::Doq => "DOQ",
        }
    }
}

/// UDP ports STUN and TURN use: 3478 and 3479 (RFC 8489), 5349 (over TLS
/// or DTLS) and Google's 19302-19309.
fn is_stun_port(port: u16) -> bool {
    matches!(port, 3478 | 3479 | 5349 | 19302..=19309)
}

/// What the destination host of a connection is, for `HOSTNAME-TYPE`
/// rules (Surge): an IPv4 or IPv6 address, a domain with a dot, or a
/// simple name without one (`localhost`, `router`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostnameType {
    Ipv4,
    Ipv6,
    Domain,
    Simple,
}

impl HostnameType {
    fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPV4",
            Self::Ipv6 => "IPV6",
            Self::Domain => "DOMAIN",
            Self::Simple => "SIMPLE",
        }
    }
}

/// Transport of a connection being routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteNetwork {
    Tcp,
    Udp,
}

/// A compiled `URL-REGEX` pattern; rules compare by its source.
#[derive(Clone)]
pub struct UrlPattern {
    source: String,
    regex: regex::Regex,
}

impl UrlPattern {
    pub fn new(source: &str) -> DomainResult<Self> {
        let invalid = |message: &str| routing_error(ROUTING_RULE_VALUE_INVALID_CODE, message);
        if source.is_empty() {
            return Err(invalid("URL-REGEX rule value must not be empty"));
        }
        let regex = regex::RegexBuilder::new(source)
            .size_limit(1 << 20)
            .build()
            .map_err(|_| invalid("URL-REGEX rule value is not a supported regex"))?;
        Ok(Self {
            source: source.to_string(),
            regex,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn is_match(&self, url: &str) -> bool {
        self.regex.is_match(url)
    }
}

impl fmt::Debug for UrlPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UrlPattern")
            .field(&self.source)
            .finish()
    }
}

impl PartialEq for UrlPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for UrlPattern {}

impl std::hash::Hash for UrlPattern {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.source.hash(state);
    }
}

/// Connection property a rule matches against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleMatcher {
    /// Exact, case-insensitive domain.
    Domain(String),
    /// The domain itself and every subdomain.
    DomainSuffix(String),
    /// Lower-case substring of the domain.
    DomainKeyword(String),
    /// Lower-case domain glob: `*` matches any run of characters (dots
    /// included) and `?` one character, as Surge `DOMAIN-WILDCARD`.
    DomainWildcard(String),
    IpCidr(IpCidr),
    /// Upper-case ISO 3166-1 alpha-2 country code.
    GeoIp(String),
    /// Autonomous system number of the destination address, as Surge
    /// `IP-ASN` (`13335` or `AS13335`). The networks come from the
    /// environment ([`RoutingEnvironment::ip_asn_matches`]); without them
    /// the rule never matches.
    IpAsn(u32),
    /// Name of a [`crate::rule_set::RuleSet`] the environment supplies.
    RuleSet(String),
    /// Lower-case GeoSite category (such as `cn` or `google`) whose domains
    /// the environment supplies.
    GeoSite(String),
    /// Destination port within an inclusive range.
    DstPort(u16, u16),
    /// Lower-case name of the local process that opened the connection,
    /// when the platform can tell.
    ProcessName(String),
    /// Address of the device or app that opened the connection, as Surge
    /// `SRC-IP` (an address or a CIDR; Clash `SRC-IP-CIDR`).
    SrcIp(IpCidr),
    /// Port the app or device opened the connection from, within an
    /// inclusive range, as Surge `SRC-PORT`.
    SrcPort(u16, u16),
    /// Local port of the inbound listener the connection came in on, within
    /// an inclusive range, as Surge `IN-PORT`. The packet tunnel has no
    /// listener port, so it never matches there.
    InPort(u16, u16),
    /// What kind of host the connection asked for, as Surge
    /// `HOSTNAME-TYPE`: a domain the connection carries (named, sniffed or
    /// from Fake-IP) decides over its address.
    HostnameType(HostnameType),
    /// The network the device is on, as Surge `SUBNET` (`SSID:<name>`,
    /// `BSSID:<mac>`, `ROUTER:<ip>`, `TYPE:WIFI|WIRED|CELLULAR`, or a CIDR
    /// one of the device's addresses is in). It never matches while the
    /// client has not reported the network
    /// ([`RoutingEnvironment::network`]).
    Subnet(NetworkCondition),
    /// Lower-case name the user gave the device that opened the connection
    /// (by its source address, [`RoutingEnvironment::device_name`]), as Surge
    /// `DEVICE-NAME`. Unnamed devices never match.
    DeviceName(String),
    /// Upper-case radio access technology of the cellular network the
    /// device is on (`LTE`, `NR`, `NRNSA`, `WCDMA` and the like), as the
    /// common rule syntax's `CELLULAR-RADIO`. It never matches off cellular or while the client
    /// has not reported the radio ([`NetworkContext::radio`]).
    CellularRadio(String),
    /// Transport of the connection, as Surge `PROTOCOL`.
    Protocol(RuleProtocol),
    /// Lower-case glob over the `User-Agent` of a plain HTTP request, as
    /// Surge `USER-AGENT` (`*` and `?`). Other flows never match.
    UserAgent(String),
    /// Regex over the URL of a plain HTTP request (`http://host/path`), as
    /// Surge `URL-REGEX`, alone with a node or group target or inside a
    /// logical rule. Other flows never match.
    UrlRegex(UrlPattern),
    /// Name of a rule script that decides, as Surge `SCRIPT`. The verdict
    /// comes from [`RoutingEnvironment::script_matches`]; a script that has
    /// not run yet stops [`RoutingModel::decide`] at this rule with
    /// [`RouteMatch::ScriptPending`]. Not accepted inside a logical rule.
    Script(String),
    /// Every rule matches.
    And(Vec<RuleMatcher>),
    /// Any rule matches.
    Or(Vec<RuleMatcher>),
    /// The rule does not match.
    Not(Box<RuleMatcher>),
}

/// Deepest nesting of AND/OR/NOT accepted.
const MAX_LOGICAL_DEPTH: usize = 8;

impl RuleMatcher {
    /// Whether matching needs a destination address: an IP rule, or a
    /// logical rule containing one.
    pub fn matches_ip(&self) -> bool {
        match self {
            Self::IpCidr(_) | Self::GeoIp(_) | Self::IpAsn(_) => true,
            Self::And(rules) | Self::Or(rules) => rules.iter().any(Self::matches_ip),
            Self::Not(rule) => rule.matches_ip(),
            _ => false,
        }
    }

    /// Whether matching may need a destination address once the
    /// environment's rule sets are known: an IP rule, a `RULE-SET` whose set
    /// holds networks or rules that match one
    /// ([`RoutingEnvironment::rule_set_needs_address`]), or a logical rule
    /// containing either. A domain-only connection is resolved before such a
    /// rule unless the rule says `no-resolve`, as the common rule syntax
    /// defines it.
    pub fn wants_address(&self, environment: &dyn RoutingEnvironment) -> bool {
        match self {
            Self::IpCidr(_) | Self::GeoIp(_) | Self::IpAsn(_) => true,
            Self::RuleSet(name) => environment.rule_set_needs_address(name),
            Self::And(rules) | Self::Or(rules) => {
                rules.iter().any(|rule| rule.wants_address(environment))
            }
            Self::Not(rule) => rule.wants_address(environment),
            _ => false,
        }
    }

    /// Whether `no-resolve` means something on this rule: an IP rule, a
    /// `RULE-SET` (whose set may hold networks), or a logical rule
    /// containing either.
    pub fn accepts_no_resolve(&self) -> bool {
        match self {
            Self::IpCidr(_) | Self::GeoIp(_) | Self::IpAsn(_) | Self::RuleSet(_) => true,
            Self::And(rules) | Self::Or(rules) => rules.iter().any(Self::accepts_no_resolve),
            Self::Not(rule) => rule.accepts_no_resolve(),
            _ => false,
        }
    }

    /// Whether the rule, or one inside it, names a rule set, a rule script
    /// or GeoSite data: matchers a rule set cannot hold, since they would
    /// reach back into the environment's sets. `GEOIP` and `IP-ASN` may sit
    /// in a set: they only look an address up in another set's networks.
    fn uses_environment_data(&self) -> bool {
        match self {
            Self::RuleSet(_) | Self::Script(_) | Self::GeoSite(_) => true,
            Self::And(rules) | Self::Or(rules) => rules.iter().any(Self::uses_environment_data),
            Self::Not(rule) => rule.uses_environment_data(),
            _ => false,
        }
    }

    /// Whether this matcher alone matches `query`, as a rule would inside
    /// [`RoutingModel::decide`] but without ever resolving a domain: an IP
    /// rule matches only a query that carries an address.
    pub fn matches(&self, query: &RouteQuery, environment: &dyn RoutingEnvironment) -> bool {
        let domain = query.domain.as_deref().map(normalize_query_domain);
        let process = query.process.as_deref().map(str::to_lowercase);
        let user_agent = query.user_agent.as_deref().map(str::to_lowercase);
        let input = MatchInput {
            domain: domain.as_deref(),
            ip: query.ip,
            port: query.port,
            source: query.source,
            source_port: query.source_port,
            in_port: query.in_port,
            dns: query.dns,
            process: process.as_deref(),
            network: query.network,
            user_agent: user_agent.as_deref(),
            url: query.url.as_deref(),
        };
        rule_matches(self, &input, environment)
    }
}

/// The rule as a line without its target, such as `DOMAIN-SUFFIX,example.com`,
/// for connection lists.
impl fmt::Display for RuleMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => write!(formatter, "DOMAIN,{domain}"),
            Self::DomainSuffix(suffix) => write!(formatter, "DOMAIN-SUFFIX,{suffix}"),
            Self::DomainKeyword(keyword) => write!(formatter, "DOMAIN-KEYWORD,{keyword}"),
            Self::DomainWildcard(pattern) => write!(formatter, "DOMAIN-WILDCARD,{pattern}"),
            Self::IpCidr(cidr) if cidr.network().is_ipv6() => write!(formatter, "IP-CIDR6,{cidr}"),
            Self::IpCidr(cidr) => write!(formatter, "IP-CIDR,{cidr}"),
            Self::GeoIp(country) => write!(formatter, "GEOIP,{country}"),
            Self::IpAsn(number) => write!(formatter, "IP-ASN,{number}"),
            Self::RuleSet(name) => write!(formatter, "RULE-SET,{name}"),
            Self::GeoSite(category) => write!(formatter, "GEOSITE,{category}"),
            Self::DstPort(start, end) if start == end => write!(formatter, "DST-PORT,{start}"),
            Self::DstPort(start, end) => write!(formatter, "DST-PORT,{start}-{end}"),
            Self::ProcessName(name) => write!(formatter, "PROCESS-NAME,{name}"),
            Self::SrcIp(cidr) => write!(formatter, "SRC-IP,{cidr}"),
            Self::SrcPort(start, end) if start == end => write!(formatter, "SRC-PORT,{start}"),
            Self::SrcPort(start, end) => write!(formatter, "SRC-PORT,{start}-{end}"),
            Self::InPort(start, end) if start == end => write!(formatter, "IN-PORT,{start}"),
            Self::InPort(start, end) => write!(formatter, "IN-PORT,{start}-{end}"),
            Self::HostnameType(kind) => write!(formatter, "HOSTNAME-TYPE,{}", kind.name()),
            Self::Subnet(condition) => write!(formatter, "SUBNET,{condition}"),
            Self::DeviceName(name) => write!(formatter, "DEVICE-NAME,{name}"),
            Self::CellularRadio(radio) => write!(formatter, "CELLULAR-RADIO,{radio}"),
            Self::Protocol(protocol) => write!(formatter, "PROTOCOL,{}", protocol.name()),
            Self::UserAgent(pattern) => write!(formatter, "USER-AGENT,{pattern}"),
            Self::UrlRegex(pattern) => write!(formatter, "URL-REGEX,{}", pattern.as_str()),
            Self::Script(name) => write!(formatter, "SCRIPT,{name}"),
            Self::And(rules) => write_logical(formatter, "AND", rules),
            Self::Or(rules) => write_logical(formatter, "OR", rules),
            Self::Not(rule) => write_logical(formatter, "NOT", std::slice::from_ref(rule)),
        }
    }
}

fn write_logical(
    formatter: &mut fmt::Formatter<'_>,
    kind: &str,
    rules: &[RuleMatcher],
) -> fmt::Result {
    write!(formatter, "{kind},(")?;
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            formatter.write_str(",")?;
        }
        write!(formatter, "({rule})")?;
    }
    formatter.write_str(")")
}

/// One ordered routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub matcher: RuleMatcher,
    pub target: PolicyTarget,
    /// For IP rules: never resolve a domain destination to match this rule.
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyGroupKind {
    /// Manually selected member.
    Select,
    /// Lowest measured latency member.
    UrlTest,
    /// First healthy member in declaration order.
    Fallback,
    /// Healthy members chosen by a hash of the destination host, so one
    /// site keeps one member (Clash `consistent-hashing`).
    LoadBalance,
    /// Healthy members in turn, one connection each.
    RoundRobin,
    /// The target of the first network rule that matches the device's
    /// current network (Wi-Fi name, router, subnet, interface type), else
    /// the default (Surge `subnet`).
    Subnet,
}

impl PolicyGroupKind {
    /// The configuration name: `select`, `url-test`, `fallback`,
    /// `load-balance`, `round-robin` or `subnet`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
            Self::RoundRobin => "round-robin",
            Self::Subnet => "subnet",
        }
    }

    /// Whether the group picks its member from health check results.
    pub fn is_health_checked(self) -> bool {
        matches!(
            self,
            Self::UrlTest | Self::Fallback | Self::LoadBalance | Self::RoundRobin
        )
    }
}

/// Kind of network interface the device uses now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkKind {
    Wifi,
    Wired,
    Cellular,
}

impl NetworkKind {
    /// `wifi`, `wired` or `cellular`, case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "wifi" | "wi-fi" | "wlan" => Some(Self::Wifi),
            "wired" | "ethernet" => Some(Self::Wired),
            "cellular" | "mobile" => Some(Self::Cellular),
            _ => None,
        }
    }
}

/// The network the device is on, as the client reports it. Every field is
/// optional: a platform that cannot read the Wi-Fi name leaves `ssid` out
/// and SSID rules never match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkContext {
    pub kind: Option<NetworkKind>,
    pub ssid: Option<String>,
    /// Lower case, colon separated.
    pub bssid: Option<String>,
    /// Default gateway.
    pub router: Option<IpAddr>,
    /// Addresses of the default interface.
    pub addresses: Vec<IpAddr>,
    /// Upper-case radio access technology on cellular (`LTE`, `NR`, ...),
    /// for `CELLULAR-RADIO` rules; `None` off cellular or when unknown.
    pub radio: Option<String>,
}

/// What a subnet group rule or a `SUBNET` rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkCondition {
    /// Exact Wi-Fi name.
    Ssid(String),
    /// Access point, lower case.
    Bssid(String),
    Router(IpAddr),
    /// An address of the device inside the network.
    Subnet(IpCidr),
    Kind(NetworkKind),
}

impl NetworkCondition {
    /// Parses `SSID:<name>`, `BSSID:<mac>`, `ROUTER:<ip>`, `SUBNET:<cidr>`,
    /// `TYPE:<wifi|wired|cellular>` or `CELLULAR`. Prefixes are
    /// case-insensitive; a Wi-Fi name keeps its case.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("cellular") {
            return Some(Self::Kind(NetworkKind::Cellular));
        }
        let (prefix, rest) = value.split_once(':')?;
        match prefix.trim().to_ascii_uppercase().as_str() {
            "SSID" if !rest.is_empty() => Some(Self::Ssid(rest.to_string())),
            "BSSID" => {
                let mac = rest.trim().to_ascii_lowercase().replace('-', ":");
                let valid = mac.split(':').count() == 6
                    && mac
                        .split(':')
                        .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()));
                valid.then_some(Self::Bssid(mac))
            }
            "ROUTER" => rest.trim().parse().ok().map(Self::Router),
            "SUBNET" => IpCidr::parse(rest.trim()).map(Self::Subnet),
            "TYPE" => NetworkKind::parse(rest).map(Self::Kind),
            _ => None,
        }
    }

    /// A `SUBNET` rule value: a condition as for [`NetworkCondition::parse`],
    /// or a bare CIDR, which is `SUBNET:<cidr>`.
    fn parse_rule_value(value: &str) -> Option<Self> {
        Self::parse(value).or_else(|| IpCidr::parse(value).map(Self::Subnet))
    }

    pub fn matches(&self, network: &NetworkContext) -> bool {
        match self {
            Self::Ssid(ssid) => network.ssid.as_deref() == Some(ssid.as_str()),
            Self::Bssid(bssid) => network
                .bssid
                .as_deref()
                .is_some_and(|found| found.eq_ignore_ascii_case(bssid)),
            Self::Router(router) => network.router == Some(*router),
            Self::Subnet(cidr) => network
                .addresses
                .iter()
                .any(|address| cidr.contains(*address)),
            Self::Kind(kind) => network.kind == Some(*kind),
        }
    }
}

impl fmt::Display for NetworkCondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssid(ssid) => write!(formatter, "SSID:{ssid}"),
            Self::Bssid(bssid) => write!(formatter, "BSSID:{bssid}"),
            Self::Router(router) => write!(formatter, "ROUTER:{router}"),
            Self::Subnet(cidr) => write!(formatter, "SUBNET:{cidr}"),
            Self::Kind(NetworkKind::Wifi) => formatter.write_str("TYPE:WIFI"),
            Self::Kind(NetworkKind::Wired) => formatter.write_str("TYPE:WIRED"),
            Self::Kind(NetworkKind::Cellular) => formatter.write_str("TYPE:CELLULAR"),
        }
    }
}

/// A validated subnet group rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    pub when: NetworkCondition,
    pub target: PolicyTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    pub url: String,
    pub interval_secs: u32,
    /// Latency difference below which url-test keeps its current member.
    pub tolerance_ms: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGroup {
    pub id: String,
    pub kind: PolicyGroupKind,
    pub members: Vec<PolicyTarget>,
    /// Initial member for select groups.
    pub default: Option<PolicyTarget>,
    /// Present for health-checked groups (see
    /// [`PolicyGroupKind::is_health_checked`]).
    pub health_check: Option<HealthCheck>,
    /// See [`PolicyGroupSpec::evaluate_before_use`].
    pub evaluate_before_use: bool,
    /// Rules of a subnet group, in order; empty for every other kind.
    pub network_rules: Vec<NetworkRule>,
}

/// Validated routing model shared by every execution engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingModel {
    pub rules: Vec<RoutingRule>,
    pub final_target: PolicyTarget,
    /// `FINAL,<target>,dns-failed`: a connection whose domain cannot be
    /// resolved for an IP rule goes to FINAL instead of being rejected.
    pub final_dns_failed: bool,
    /// `FINAL,<target>,dns-continue` (what Clash subscriptions import to): a
    /// connection whose domain cannot be resolved for an IP rule is matched
    /// on without an address, so IP rules do not match it and the rules
    /// after them still do, as in Clash and mihomo. Needs an environment
    /// that reports the failed lookup ([`RoutingEnvironment::resolve_failed`]);
    /// until then the rule asks for the address as without the option.
    pub final_dns_continue: bool,
    pub groups: Vec<PolicyGroup>,
}

/// Rule line parsed without resolving its target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLine {
    Rule {
        matcher: RuleMatcher,
        target: String,
        no_resolve: bool,
    },
    Final {
        target: String,
        /// `dns-failed`: see [`RoutingModel::final_dns_failed`].
        dns_failed: bool,
        /// `dns-continue`: see [`RoutingModel::final_dns_continue`].
        dns_continue: bool,
    },
}

/// Parses one Loon-style rule line such as `DOMAIN-SUFFIX,example.com,Proxy`
/// or a Surge-style logical rule such as
/// `AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy`.
pub fn parse_rule_line(line: &str) -> DomainResult<RuleLine> {
    let line = line.trim();
    let (head, rest) = line.split_once(',').unwrap_or((line, ""));
    let head = head.trim().to_ascii_uppercase();
    if is_logical(&head) {
        let (inner, after) = split_parenthesized(rest)?;
        let matcher = parse_logical(&head, inner, 1)?;
        let after = after.trim_start();
        let tail = after.strip_prefix(',').ok_or_else(|| {
            routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "logical rule must be followed by a target",
            )
        })?;
        let parts = tail.split(',').map(str::trim).collect::<Vec<_>>();
        if parts[0].is_empty() {
            return Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "logical rule must be followed by a target",
            ));
        }
        let no_resolve = parse_options(&parts[1..], &matcher)?;
        return Ok(RuleLine::Rule {
            matcher,
            target: parts[0].to_string(),
            no_resolve,
        });
    }

    let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
    let kind = parts[0].to_ascii_uppercase();
    if kind == "FINAL" {
        return match parts.as_slice() {
            [_, target] if !target.is_empty() => Ok(RuleLine::Final {
                target: (*target).to_string(),
                dns_failed: false,
                dns_continue: false,
            }),
            [_, target, option]
                if !target.is_empty() && option.eq_ignore_ascii_case("dns-failed") =>
            {
                Ok(RuleLine::Final {
                    target: (*target).to_string(),
                    dns_failed: true,
                    dns_continue: false,
                })
            }
            [_, target, option]
                if !target.is_empty() && option.eq_ignore_ascii_case("dns-continue") =>
            {
                Ok(RuleLine::Final {
                    target: (*target).to_string(),
                    dns_failed: false,
                    dns_continue: true,
                })
            }
            _ => Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "FINAL rule must have exactly one target, optionally followed by dns-failed or dns-continue",
            )),
        };
    }

    if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "routing rule must have a type, a value, and a target",
        ));
    }
    if kind == "URL-REGEX" && is_reject_target(parts[2]) {
        // A standalone URL-REGEX that rejects is the MITM core's (its rejects
        // run on the full URL of every intercepted request). One that picks
        // a node or group routes each request: plain HTTP flows by their
        // first request, decrypted ones request by request.
        return Err(routing_error(
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
            "URL-REGEX with REJECT belongs to HTTPS decryption; as a routing rule it needs a node or group, or AND, OR, NOT",
        ));
    }
    let matcher = parse_matcher(&kind, parts[1])?;
    let no_resolve = parse_options(&parts[3..], &matcher)?;
    Ok(RuleLine::Rule {
        matcher,
        target: parts[2].to_string(),
        no_resolve,
    })
}

fn parse_options(options: &[&str], matcher: &RuleMatcher) -> DomainResult<bool> {
    let mut no_resolve = false;
    for option in options {
        if option.eq_ignore_ascii_case("no-resolve") && matcher.accepts_no_resolve() {
            no_resolve = true;
        } else if option.eq_ignore_ascii_case("no-resolve")
            && matches!(matcher, RuleMatcher::SrcIp(_))
        {
            // Clash writes it on SRC-IP-CIDR; a source address never needs
            // a lookup.
        } else if option.eq_ignore_ascii_case("pre-matching")
            || option.eq_ignore_ascii_case("extended-matching")
        {
            // Surge options: matching before DNS is how rules already run,
            // and SNI/Host matching needs no option here.
        } else {
            return Err(routing_error(
                ROUTING_RULE_OPTION_UNSUPPORTED_CODE,
                "routing rule option is unsupported; only IP and RULE-SET rules accept no-resolve",
            ));
        }
    }
    Ok(no_resolve)
}

fn is_logical(kind: &str) -> bool {
    matches!(kind, "AND" | "OR" | "NOT")
}

/// Splits `(inner)rest` at the parenthesis matching the first one.
fn split_parenthesized(text: &str) -> DomainResult<(&str, &str)> {
    let invalid = || {
        routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rule needs balanced parentheses, as in AND,((DOMAIN,a.com),(DST-PORT,443))",
        )
    };
    let text = text.trim_start();
    if !text.starts_with('(') {
        return Err(invalid());
    }
    let mut depth = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&text[1..index], &text[index + 1..]));
                }
            }
            _ => {}
        }
    }
    Err(invalid())
}

/// Parses the parenthesized rules inside a logical rule, `(A,a),(B,b)`.
fn parse_logical(kind: &str, inner: &str, depth: usize) -> DomainResult<RuleMatcher> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rules are nested too deeply",
        ));
    }
    let mut rules = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        let (item, after) = split_parenthesized(rest)?;
        rules.push(parse_sub_rule(item, depth)?);
        let after = after.trim_start();
        rest = match after.strip_prefix(',') {
            Some(next) => next.trim_start(),
            None if after.is_empty() => after,
            None => {
                return Err(routing_error(
                    ROUTING_RULE_LINE_INVALID_CODE,
                    "rules inside a logical rule must be separated by commas",
                ))
            }
        };
    }
    match (kind, rules.len()) {
        (_, 0) => Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rule must contain at least one rule",
        )),
        ("NOT", 1) => Ok(RuleMatcher::Not(Box::new(rules.remove(0)))),
        ("NOT", _) => Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "NOT rule must contain exactly one rule",
        )),
        ("AND", _) => Ok(RuleMatcher::And(rules)),
        _ => Ok(RuleMatcher::Or(rules)),
    }
}

/// One rule inside a logical rule: a type and a value, or another logical
/// rule, without a target.
fn parse_sub_rule(text: &str, depth: usize) -> DomainResult<RuleMatcher> {
    let (kind, value) = text.split_once(',').ok_or_else(|| {
        routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "rule inside a logical rule must have a type and a value",
        )
    })?;
    let kind = kind.trim().to_ascii_uppercase();
    if is_logical(&kind) {
        let (inner, after) = split_parenthesized(value)?;
        if !after.trim().is_empty() {
            return Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "rule inside a logical rule has no target",
            ));
        }
        return parse_logical(&kind, inner, depth + 1);
    }
    if kind == "SCRIPT" {
        return Err(routing_error(
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
            "SCRIPT rules cannot be used inside AND, OR, or NOT",
        ));
    }
    let mut parts = value.split(',').map(str::trim);
    let value = parts.next().unwrap_or_default();
    // `no-resolve` is accepted for compatibility; a logical rule resolves as
    // its own options say.
    if parts.any(|option| !option.eq_ignore_ascii_case("no-resolve")) || value.is_empty() {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "rule inside a logical rule must have a type and a value",
        ));
    }
    parse_matcher(&kind, value)
}

/// One line of a downloaded rule set that is not a plain domain or network:
/// `TYPE,value` (an optional `no-resolve` is ignored, as the `RULE-SET` rule
/// decides) or `AND|OR|NOT,(...)`, with no target. Rule sets, rule scripts
/// and GeoSite data are refused: a set cannot reach back into the
/// environment's sets. `GEOIP` and `IP-ASN` are kept, since they only look
/// the address up in another set's networks. The error names nothing from
/// the line.
pub(crate) fn parse_rule_set_entry(line: &str) -> DomainResult<RuleMatcher> {
    let matcher = parse_sub_rule(line, 1)?;
    if matcher.uses_environment_data() {
        return Err(routing_error(
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
            "a rule set cannot hold RULE-SET, SCRIPT or GEOSITE rules",
        ));
    }
    Ok(matcher)
}

/// The matcher of a rule type and its value.
fn parse_matcher(kind: &str, value: &str) -> DomainResult<RuleMatcher> {
    Ok(match kind {
        "DOMAIN" => RuleMatcher::Domain(normalize_rule_domain(value)?),
        "DOMAIN-SUFFIX" => {
            RuleMatcher::DomainSuffix(normalize_rule_domain(value.trim_start_matches('.'))?)
        }
        "DOMAIN-KEYWORD" => RuleMatcher::DomainKeyword(normalize_rule_domain(value)?),
        "DOMAIN-WILDCARD" => RuleMatcher::DomainWildcard(normalize_domain_wildcard(value)?),
        "IP-CIDR" | "IP-CIDR6" => RuleMatcher::IpCidr(IpCidr::parse(value).ok_or_else(|| {
            routing_error(
                ROUTING_RULE_VALUE_INVALID_CODE,
                "IP-CIDR rule value must be an address with a prefix length",
            )
        })?),
        "GEOIP" => RuleMatcher::GeoIp(normalize_country_code(value)?),
        "IP-ASN" => RuleMatcher::IpAsn(parse_asn(value)?),
        "RULE-SET" => RuleMatcher::RuleSet(value.to_string()),
        "GEOSITE" => RuleMatcher::GeoSite(normalize_category(value)?),
        "DST-PORT" | "DEST-PORT" => {
            let (start, end) = parse_port_range(value)?;
            RuleMatcher::DstPort(start, end)
        }
        "IN-PORT" => {
            let (start, end) = parse_port_range(value).map_err(|_| {
                routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "IN-PORT rule value must be a port or a start-end range",
                )
            })?;
            RuleMatcher::InPort(start, end)
        }
        "SRC-IP" | "SRC-IP-CIDR" => RuleMatcher::SrcIp(parse_source(value)?),
        "SRC-PORT" => {
            let (start, end) = parse_port_range(value).map_err(|_| {
                routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "SRC-PORT rule value must be a port or a start-end range",
                )
            })?;
            RuleMatcher::SrcPort(start, end)
        }
        "HOSTNAME-TYPE" => {
            RuleMatcher::HostnameType(match value.trim().to_ascii_uppercase().as_str() {
                "IPV4" => HostnameType::Ipv4,
                "IPV6" => HostnameType::Ipv6,
                "DOMAIN" => HostnameType::Domain,
                "SIMPLE" => HostnameType::Simple,
                _ => {
                    return Err(routing_error(
                        ROUTING_RULE_VALUE_INVALID_CODE,
                        "HOSTNAME-TYPE rule value must be IPV4, IPV6, DOMAIN, or SIMPLE",
                    ))
                }
            })
        }
        "SUBNET" => RuleMatcher::Subnet(NetworkCondition::parse_rule_value(value).ok_or_else(
            || {
                routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "SUBNET rule value must be SSID:<name>, BSSID:<mac>, ROUTER:<ip>, TYPE:WIFI, TYPE:WIRED, TYPE:CELLULAR, or a CIDR",
                )
            },
        )?),
        "DEVICE-NAME" => {
            let name = value.trim().trim_matches('"').to_lowercase();
            if name.is_empty() || name.chars().count() > 64 {
                return Err(routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "DEVICE-NAME rule value must be a device name of 1-64 characters",
                ));
            }
            RuleMatcher::DeviceName(name)
        }
        "CELLULAR-RADIO" => {
            let radio = value.trim().to_ascii_uppercase();
            let valid = !radio.is_empty()
                && radio.len() <= 24
                && radio.bytes().all(|byte| byte.is_ascii_alphanumeric());
            if !valid {
                return Err(routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "CELLULAR-RADIO rule value must be a radio technology such as LTE or NR",
                ));
            }
            RuleMatcher::CellularRadio(radio)
        }
        "PROCESS-NAME" => RuleMatcher::ProcessName(value.trim().to_lowercase()),
        "USER-AGENT" => {
            let pattern = value.trim().trim_matches('"').to_lowercase();
            if pattern.is_empty() {
                return Err(routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "USER-AGENT rule value must not be empty",
                ));
            }
            RuleMatcher::UserAgent(pattern)
        }
        "URL-REGEX" => RuleMatcher::UrlRegex(UrlPattern::new(value.trim().trim_matches('"'))?),
        "SCRIPT" => {
            let name = value.trim();
            let valid = !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
            if !valid {
                return Err(routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "SCRIPT rule value must be a script name of 1-128 characters of [A-Za-z0-9._-]",
                ));
            }
            RuleMatcher::Script(name.to_string())
        }
        "PROTOCOL" => RuleMatcher::Protocol(match value.trim().to_ascii_uppercase().as_str() {
            "TCP" => RuleProtocol::Tcp,
            "UDP" => RuleProtocol::Udp,
            "QUIC" => RuleProtocol::Quic,
            "HTTP" => RuleProtocol::Http,
            "HTTPS" => RuleProtocol::Https,
            "STUN" => RuleProtocol::Stun,
            "DOH" => RuleProtocol::Doh,
            "DOQ" => RuleProtocol::Doq,
            _ => {
                return Err(routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "PROTOCOL rule value must be TCP, UDP, QUIC, HTTP, HTTPS, STUN, DOH, or DOQ",
                ))
            }
        }),
        _ => return Err(routing_error(
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
            "routing rule type must be DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-WILDCARD, IP-CIDR, IP-CIDR6, GEOIP, IP-ASN, GEOSITE, DST-PORT, SRC-IP, SRC-PORT, IN-PORT, PROCESS-NAME, HOSTNAME-TYPE, SUBNET, DEVICE-NAME, CELLULAR-RADIO, PROTOCOL, USER-AGENT, URL-REGEX, RULE-SET, SCRIPT, AND, OR, NOT, or FINAL",
        )),
    })
}

/// A `SRC-IP` value: an address (one host) or a CIDR; IPv6 may be written
/// in brackets.
fn parse_source(value: &str) -> DomainResult<IpCidr> {
    let value = value.trim();
    let unbracketed = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(address, rest)| format!("{address}{rest}"));
    let value = unbracketed.as_deref().unwrap_or(value);
    let parsed = if value.contains('/') {
        IpCidr::parse(value)
    } else {
        value.parse::<IpAddr>().ok().and_then(|address| {
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            IpCidr::parse(&format!("{address}/{prefix}"))
        })
    };
    parsed.ok_or_else(|| {
        routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "SRC-IP rule value must be an address or an address with a prefix length",
        )
    })
}

/// A port or an inclusive `start-end` range.
fn parse_port_range(value: &str) -> DomainResult<(u16, u16)> {
    let invalid = || {
        routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "DST-PORT rule value must be a port or a start-end range",
        )
    };
    let port = |text: &str| text.trim().parse::<u16>().map_err(|_| invalid());
    let (start, end) = match value.split_once('-') {
        Some((start, end)) => (port(start)?, port(end)?),
        None => {
            let port = port(value)?;
            (port, port)
        }
    };
    if start > end {
        return Err(invalid());
    }
    Ok((start, end))
}

fn normalize_category(value: &str) -> DomainResult<String> {
    let category = value.trim().to_ascii_lowercase();
    let valid = !category.is_empty()
        && category.len() <= 64
        && category
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'!' | b'@' | b'.'));
    if valid {
        Ok(category)
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "GEOSITE rule value must be a category name such as cn or google",
        ))
    }
}

impl RoutingModel {
    /// Validates a routing spec against the node ids that can be referenced.
    pub fn from_spec(spec: &RoutingSpec, node_ids: &BTreeSet<String>) -> DomainResult<Self> {
        let names = TargetNames::collect(&spec.groups, node_ids)?;
        let groups = spec
            .groups
            .iter()
            .map(|group| normalize_group(group, &names))
            .collect::<DomainResult<Vec<_>>>()?;
        reject_group_cycles(&groups)?;

        let mut rules = Vec::with_capacity(spec.rules.len());
        let mut final_target = None;
        let mut final_dns_failed = false;
        let mut final_dns_continue = false;
        for (index, line) in spec.rules.iter().enumerate() {
            if final_target.is_some() {
                return Err(routing_error(
                    ROUTING_FINAL_NOT_LAST_CODE,
                    format!("routing rule {index} follows the FINAL rule"),
                ));
            }
            match parse_rule_line(line).map_err(|error| with_rule_index(error, index))? {
                RuleLine::Rule {
                    matcher,
                    target,
                    no_resolve,
                } => rules.push(RoutingRule {
                    matcher,
                    target: names
                        .resolve(&target)
                        .map_err(|error| with_rule_index(error, index))?,
                    no_resolve,
                }),
                RuleLine::Final {
                    target,
                    dns_failed,
                    dns_continue,
                } => {
                    final_target = Some(
                        names
                            .resolve(&target)
                            .map_err(|error| with_rule_index(error, index))?,
                    );
                    final_dns_failed = dns_failed;
                    final_dns_continue = dns_continue;
                }
            }
        }

        let final_target = final_target.ok_or_else(|| {
            routing_error(
                ROUTING_FINAL_MISSING_CODE,
                "routing rules must end with a FINAL rule",
            )
        })?;
        Ok(Self {
            rules,
            final_target,
            final_dns_failed,
            final_dns_continue,
            groups,
        })
    }

    pub fn group(&self, id: &str) -> Option<&PolicyGroup> {
        self.groups.iter().find(|group| group.id == id)
    }

    /// Decides where a connection goes, resolving policy groups to a node.
    ///
    /// Rules are evaluated in order. The first IP rule without `no-resolve`
    /// (or `RULE-SET` whose set holds networks, after its domains missed)
    /// asks the environment to resolve a domain-only destination once; like a
    /// sing-box `resolve` action, the resolved address is then used by every
    /// later IP rule and is reported in the result. As in sing-box, a failed
    /// resolution rejects the connection instead of falling through to FINAL,
    /// unless FINAL says `dns-failed` (Surge): the connection then goes to
    /// FINAL's target, reported as [`RouteMatch::FinalAfterResolveFailed`];
    /// or `dns-continue` (Clash): once the environment reports the failed
    /// lookup ([`RoutingEnvironment::resolve_failed`]) the IP rules do not
    /// match and the later rules are tried without an address. Before that,
    /// the rule reports [`RouteMatch::ResolveFailed`] so the caller looks
    /// the name up.
    pub fn decide(
        &self,
        query: &RouteQuery,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        let domain = query.domain.as_deref().map(normalize_query_domain);
        self.decide_over(
            (0..self.rules.len()).map(|index| (index, false)),
            None,
            domain,
            query,
            environment,
        )
    }

    /// [`RoutingModel::decide`] with the DOMAIN and DOMAIN-SUFFIX rules
    /// looked up in `index` instead of tried one by one; the result is the
    /// same. An index built for a different rule list (see
    /// [`RuleIndex::fits`]) is ignored and every rule is tried.
    pub fn decide_indexed(
        &self,
        index: &RuleIndex,
        query: &RouteQuery,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        if !index.fits(self) {
            return self.decide(query, environment);
        }
        let domain = query.domain.as_deref().map(normalize_query_domain);
        let first = domain
            .as_deref()
            .and_then(|domain| index.first_domain_match(domain));
        let before = index
            .others
            .partition_point(|&(rule, _)| first.is_none_or(|first| rule < first));
        self.decide_over(
            index.others[..before].iter().copied(),
            first,
            domain,
            query,
            environment,
        )
    }

    /// Tries the rules at `candidates` (ascending) in order, passing over
    /// those flagged as needing an address while there is none; when none
    /// matches, the rule at `matched_after` is the match, else FINAL.
    fn decide_over(
        &self,
        candidates: impl Iterator<Item = (usize, bool)>,
        matched_after: Option<usize>,
        domain: Option<String>,
        query: &RouteQuery,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        let process = query.process.as_deref().map(str::to_lowercase);
        let user_agent = query.user_agent.as_deref().map(str::to_lowercase);
        let url = query.url.as_deref();
        let mut ip = query.ip;
        let mut resolved_ip = None;
        let mut resolve_attempted = false;
        let balance_key = domain.clone().or_else(|| query.ip.map(|ip| ip.to_string()));

        for (index, needs_ip) in candidates {
            if needs_ip && ip.is_none() {
                continue;
            }
            let rule = &self.rules[index];
            if ip.is_none()
                && !rule.no_resolve
                && !resolve_attempted
                && rule.matcher.wants_address(environment)
            {
                if let (RuleMatcher::RuleSet(_), Some(_)) = (&rule.matcher, domain.as_deref()) {
                    // A set is tried on the domain first, so a connection its
                    // domains hold is never resolved for its networks.
                    let input = MatchInput {
                        domain: domain.as_deref(),
                        ip: None,
                        port: query.port,
                        source: query.source,
                        source_port: query.source_port,
                        in_port: query.in_port,
                        dns: query.dns,
                        process: process.as_deref(),
                        network: query.network,
                        user_agent: user_agent.as_deref(),
                        url,
                    };
                    if rule_matches(&rule.matcher, &input, environment) {
                        return self.resolution(
                            RouteMatch::Rule(index),
                            &rule.target,
                            resolved_ip,
                            balance_key.as_deref(),
                            environment,
                        );
                    }
                }
                resolve_attempted = true;
                if let Some(domain) = domain.as_deref() {
                    resolved_ip = environment.resolve(domain);
                    if resolved_ip.is_none() && self.final_dns_failed {
                        return self.resolution(
                            RouteMatch::FinalAfterResolveFailed(index),
                            &self.final_target,
                            None,
                            balance_key.as_deref(),
                            environment,
                        );
                    }
                    // `dns-continue` after a failed lookup (Clash): the
                    // address stays unknown, so no IP rule matches and the
                    // other rules still do.
                    let continues = self.final_dns_continue && environment.resolve_failed();
                    if resolved_ip.is_none() && !continues {
                        return RouteResolution {
                            matched: RouteMatch::ResolveFailed(index),
                            target: PolicyTarget::Reject(RejectKind::Reject),
                            group_path: Vec::new(),
                            outcome: RouteOutcome::Reject(RejectKind::Reject),
                            resolved_ip: None,
                        };
                    }
                    ip = resolved_ip;
                }
            }
            if let RuleMatcher::Script(name) = &rule.matcher {
                match environment.script_matches(name) {
                    Some(true) => {
                        return self.resolution(
                            RouteMatch::Rule(index),
                            &rule.target,
                            resolved_ip,
                            balance_key.as_deref(),
                            environment,
                        )
                    }
                    Some(false) => continue,
                    None => {
                        return RouteResolution {
                            matched: RouteMatch::ScriptPending(index),
                            target: PolicyTarget::Reject(RejectKind::Reject),
                            group_path: Vec::new(),
                            outcome: RouteOutcome::Reject(RejectKind::Reject),
                            resolved_ip,
                        }
                    }
                }
            }
            let input = MatchInput {
                domain: domain.as_deref(),
                ip,
                port: query.port,
                source: query.source,
                source_port: query.source_port,
                in_port: query.in_port,
                dns: query.dns,
                process: process.as_deref(),
                network: query.network,
                user_agent: user_agent.as_deref(),
                url,
            };
            if rule_matches(&rule.matcher, &input, environment) {
                return self.resolution(
                    RouteMatch::Rule(index),
                    &rule.target,
                    resolved_ip,
                    balance_key.as_deref(),
                    environment,
                );
            }
        }

        if let Some(index) = matched_after {
            return self.resolution(
                RouteMatch::Rule(index),
                &self.rules[index].target,
                resolved_ip,
                balance_key.as_deref(),
                environment,
            );
        }
        self.resolution(
            RouteMatch::Final,
            &self.final_target,
            resolved_ip,
            balance_key.as_deref(),
            environment,
        )
    }

    /// Sends a connection straight to `target`, skipping the rules, as a
    /// global mode does. The result reports [`RouteMatch::Final`].
    pub fn route_to(
        &self,
        target: &PolicyTarget,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        self.resolution(RouteMatch::Final, target, None, None, environment)
    }

    /// The member a group currently picks: the selected or default member of
    /// a select group, the fastest of a url-test group, the first healthy
    /// member of a fallback, load-balance or round-robin group (which pick
    /// per connection when routing).
    pub fn group_member(
        &self,
        group_id: &str,
        environment: &dyn RoutingEnvironment,
    ) -> Option<PolicyTarget> {
        self.group(group_id)
            .map(|group| select_group_member(group, None, environment))
    }

    /// Looks up a configuration name the way rule targets are resolved:
    /// DIRECT, a REJECT policy, a policy group id or a node id.
    pub fn target_named(&self, name: &str, node_ids: &BTreeSet<String>) -> Option<PolicyTarget> {
        let name = name.trim();
        if name.eq_ignore_ascii_case(RESERVED_DIRECT) {
            Some(PolicyTarget::Direct)
        } else if let Some(kind) = RejectKind::parse(name) {
            Some(PolicyTarget::Reject(kind))
        } else if self.group(name).is_some() {
            Some(PolicyTarget::Group(name.to_string()))
        } else if node_ids.contains(name) {
            Some(PolicyTarget::Node(name.to_string()))
        } else {
            None
        }
    }

    /// `balance_key` is the destination host of a routed connection, which
    /// load-balance and round-robin groups pick a member for.
    fn resolution(
        &self,
        matched: RouteMatch,
        target: &PolicyTarget,
        resolved_ip: Option<IpAddr>,
        balance_key: Option<&str>,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        let mut group_path = Vec::new();
        let mut current = target.clone();
        while let PolicyTarget::Group(id) = &current {
            let Some(group) = self.group(id) else { break };
            if group_path.contains(&group.id) {
                break;
            }
            group_path.push(group.id.clone());
            current = select_group_member(group, balance_key, environment);
        }

        let outcome = match current {
            PolicyTarget::Direct | PolicyTarget::Group(_) => RouteOutcome::Direct,
            PolicyTarget::Reject(kind) => RouteOutcome::Reject(kind),
            PolicyTarget::Node(id) => RouteOutcome::Node(id),
        };
        RouteResolution {
            matched,
            target: target.clone(),
            group_path,
            outcome,
            resolved_ip,
        }
    }
}

/// Hash lookup for the DOMAIN and DOMAIN-SUFFIX rules of a
/// [`RoutingModel`], which are most of a large subscription: a decision then
/// tries only the other rules that come before the first domain rule that
/// matches, instead of every rule. Build it again whenever the rule list
/// changes; [`RoutingModel::decide_indexed`] ignores an index whose rule
/// count no longer fits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleIndex {
    rule_count: usize,
    /// First rule index of each exact domain.
    exact: HashMap<String, usize>,
    /// First rule index of each suffix (without a leading dot).
    suffix: HashMap<String, usize>,
    /// Every other rule, ascending, with whether it is an IP-CIDR or GEOIP
    /// rule marked `no-resolve`: such a rule neither matches nor resolves
    /// while the connection has no address, so it is passed over then.
    others: Vec<(usize, bool)>,
}

impl RuleIndex {
    pub fn new(model: &RoutingModel) -> Self {
        let mut index = Self {
            rule_count: model.rules.len(),
            ..Self::default()
        };
        for (position, rule) in model.rules.iter().enumerate() {
            match &rule.matcher {
                RuleMatcher::Domain(domain) => {
                    index.exact.entry(domain.clone()).or_insert(position);
                }
                // A suffix with a leading dot or none at all matches in ways
                // a lookup by label does not reproduce; it stays in order.
                RuleMatcher::DomainSuffix(suffix)
                    if !suffix.is_empty() && !suffix.starts_with('.') =>
                {
                    index.suffix.entry(suffix.clone()).or_insert(position);
                }
                matcher => index.others.push((
                    position,
                    rule.no_resolve
                        && matches!(
                            matcher,
                            RuleMatcher::IpCidr(_) | RuleMatcher::GeoIp(_) | RuleMatcher::IpAsn(_)
                        ),
                )),
            }
        }
        index
    }

    /// Whether this index was built for a model with `model`'s rule count.
    pub fn fits(&self, model: &RoutingModel) -> bool {
        self.rule_count == model.rules.len()
    }

    /// Rules tried one by one: those that are neither DOMAIN nor
    /// DOMAIN-SUFFIX.
    pub fn unindexed_len(&self) -> usize {
        self.others.len()
    }

    /// The first DOMAIN or DOMAIN-SUFFIX rule matching the normalized
    /// `domain`: an exact rule for the domain, or a suffix rule for the
    /// domain itself or any part of it after a dot.
    fn first_domain_match(&self, domain: &str) -> Option<usize> {
        let mut first = self.exact.get(domain).copied();
        let mut keep = |found: Option<&usize>| {
            if let Some(&found) = found {
                first = Some(first.map_or(found, |current: usize| current.min(found)));
            }
        };
        keep(self.suffix.get(domain));
        for (dot, _) in domain.match_indices('.') {
            keep(self.suffix.get(&domain[dot + 1..]));
        }
        first
    }
}

/// Destination of a connection being routed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteQuery {
    /// Destination domain, when known (for example from FakeIP or sniffing).
    pub domain: Option<String>,
    /// Destination address, when the connection targets an IP.
    pub ip: Option<IpAddr>,
    /// Destination port, for DST-PORT rules.
    pub port: Option<u16>,
    /// Name of the local process that opened the connection, for
    /// PROCESS-NAME rules, when the platform can tell.
    pub process: Option<String>,
    /// Transport, for PROTOCOL rules; they never match without it.
    pub network: Option<RouteNetwork>,
    /// `User-Agent` of a plain HTTP request, for USER-AGENT rules.
    pub user_agent: Option<String>,
    /// URL of a plain HTTP request, for URL-REGEX rules.
    pub url: Option<String>,
    /// Address of the device or app that opened the connection, for SRC-IP
    /// rules.
    pub source: Option<IpAddr>,
    /// Local port of the inbound listener the connection came in on, for
    /// IN-PORT rules.
    pub in_port: Option<u16>,
    /// Port the app or device opened the connection from, for SRC-PORT
    /// rules.
    pub source_port: Option<u16>,
    /// The connection is the engine's own encrypted DNS query to a proxied
    /// server, for `PROTOCOL,DOH` and `PROTOCOL,DOQ` rules:
    /// [`RuleProtocol::Doh`] or [`RuleProtocol::Doq`].
    pub dns: Option<RuleProtocol>,
}

impl RouteQuery {
    pub fn domain(domain: impl Into<String>) -> Self {
        Self {
            domain: Some(domain.into()),
            ..Self::default()
        }
    }

    pub fn ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            ..Self::default()
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_network(mut self, network: RouteNetwork) -> Self {
        self.network = Some(network);
        self
    }

    /// Sets the source address and inbound port, for SRC-IP and IN-PORT.
    pub fn with_source(mut self, source: Option<IpAddr>, in_port: Option<u16>) -> Self {
        self.source = source;
        self.in_port = in_port;
        self
    }

    /// Sets the port the connection was opened from, for SRC-PORT.
    pub fn with_source_port(mut self, port: Option<u16>) -> Self {
        self.source_port = port;
        self
    }
}

/// Runtime inputs an execution engine supplies to [`RoutingModel::decide`].
///
/// Every method has a conservative default so a static environment is enough
/// for snapshot tests: no DNS, no GeoIP database, and no health results.
pub trait RoutingEnvironment {
    /// Country code for an address, compared case-insensitively.
    fn geoip_country(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    /// Whether `ip` is in the upper-case `country`; by default it compares
    /// [`RoutingEnvironment::geoip_country`].
    fn geoip_matches(&self, country: &str, ip: IpAddr) -> bool {
        self.geoip_country(ip)
            .is_some_and(|found| found.eq_ignore_ascii_case(country))
    }

    /// Whether `ip` belongs to the autonomous system `number`; nothing by
    /// default, since no ASN data is built in.
    fn ip_asn_matches(&self, _number: u32, _ip: IpAddr) -> bool {
        false
    }

    /// Whether the lower-case GeoSite `category` holds `domain` (lower case,
    /// no trailing dot); an unknown category matches nothing.
    fn geosite_matches(&self, _category: &str, _domain: &str) -> bool {
        false
    }

    /// Resolves a domain for IP rules that allow resolution; `None` means the
    /// lookup failed (or was not made yet) and the connection is rejected,
    /// unless FINAL says `dns-failed` or `dns-continue`.
    fn resolve(&self, _domain: &str) -> Option<IpAddr> {
        None
    }

    /// Whether the lookup [`Self::resolve`] stands for was made for this
    /// connection and failed, so `dns-continue` matches on without an
    /// address. `false` (the default) when no lookup was made yet: the
    /// decision then asks for one ([`RouteMatch::ResolveFailed`]).
    fn resolve_failed(&self) -> bool {
        false
    }

    /// Member name currently chosen in a select group.
    fn selected_member(&self, _group_id: &str) -> Option<String> {
        None
    }

    /// Last measured latency of a url-test or fallback member; `None` means
    /// untested or failed.
    fn member_latency_ms(&self, _group_id: &str, _member: &PolicyTarget) -> Option<u32> {
        None
    }

    /// A counter that grows by one per call, for the round-robin group
    /// `group_id`; called once for each connection the group routes.
    fn round_robin(&self, _group_id: &str) -> usize {
        0
    }

    /// The member a url-test group used until now. The group keeps it
    /// while no other member is faster by more than the group's tolerance,
    /// so two members a few milliseconds apart do not trade places on
    /// every check.
    fn url_test_current(&self, _group_id: &str) -> Option<String> {
        None
    }

    /// The network the device is on, for subnet groups and `SUBNET` and
    /// `CELLULAR-RADIO` rules; `None` when the client has not said, and then
    /// every subnet group uses its default and those rules never match.
    fn network(&self) -> Option<&NetworkContext> {
        None
    }

    /// The name the user gave the device at `source` (the address a
    /// connection came from), for `DEVICE-NAME` rules; compared
    /// case-insensitively. No device has one by default.
    fn device_name(&self, _source: IpAddr) -> Option<&str> {
        None
    }

    /// Verdict of the rule script `name` (a `SCRIPT` rule) for the
    /// connection being routed. `None` means it has not run yet:
    /// [`RoutingModel::decide`] then stops at that rule with
    /// [`RouteMatch::ScriptPending`] so the caller can run the script, which
    /// may take a while, outside the decision and decide again. By default
    /// no script matches.
    fn script_matches(&self, _name: &str) -> Option<bool> {
        Some(false)
    }

    /// Whether the named rule set holds the destination; an unknown set
    /// matches nothing.
    fn rule_set_matches(&self, _name: &str, _domain: Option<&str>, _ip: Option<IpAddr>) -> bool {
        false
    }

    /// Whether the named rule set holds networks, or rules that match an
    /// address ([`crate::rule_set::RuleSet::needs_address`]), so a
    /// domain-only connection is resolved for it unless the `RULE-SET` rule
    /// says `no-resolve`. An unknown set needs none.
    fn rule_set_needs_address(&self, _name: &str) -> bool {
        false
    }

    /// The rules of the named set other than its domains and networks
    /// ([`crate::rule_set::RuleSet::rules`]), tried one by one after them.
    fn rule_set_rules(&self, _name: &str) -> &[RuleMatcher] {
        &[]
    }
}

/// Environment with no runtime state: select groups use their default and
/// health-checked groups use their first member.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticRoutingEnvironment;

impl RoutingEnvironment for StaticRoutingEnvironment {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatch {
    /// Index into [`RoutingModel::rules`].
    Rule(usize),
    /// Resolving the domain for the IP rule at this index failed.
    ResolveFailed(usize),
    /// Resolving the domain for the IP rule at this index failed, and FINAL
    /// says `dns-failed`, so FINAL's target took the connection.
    FinalAfterResolveFailed(usize),
    /// The SCRIPT rule at this index has no verdict yet
    /// ([`RoutingEnvironment::script_matches`] returned `None`): the caller
    /// runs the script and decides again with its verdict. The resolution
    /// rejects and carries the address resolved so far.
    ScriptPending(usize),
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    Direct,
    Reject(RejectKind),
    Node(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    pub matched: RouteMatch,
    /// Target named by the matched rule or FINAL.
    pub target: PolicyTarget,
    /// Groups traversed from `target` to `outcome`, outermost first.
    pub group_path: Vec<String>,
    pub outcome: RouteOutcome,
    /// Address obtained by resolving the domain for an IP rule.
    pub resolved_ip: Option<IpAddr>,
}

/// What one connection offers the rules, normalized.
struct MatchInput<'a> {
    domain: Option<&'a str>,
    ip: Option<IpAddr>,
    port: Option<u16>,
    source: Option<IpAddr>,
    source_port: Option<u16>,
    in_port: Option<u16>,
    dns: Option<RuleProtocol>,
    process: Option<&'a str>,
    network: Option<RouteNetwork>,
    user_agent: Option<&'a str>,
    url: Option<&'a str>,
}

fn rule_matches(
    matcher: &RuleMatcher,
    input: &MatchInput<'_>,
    environment: &dyn RoutingEnvironment,
) -> bool {
    let (domain, ip) = (input.domain, input.ip);
    match matcher {
        RuleMatcher::Domain(expected) => domain == Some(expected.as_str()),
        RuleMatcher::DomainKeyword(keyword) => {
            domain.is_some_and(|domain| domain.contains(keyword.as_str()))
        }
        RuleMatcher::DomainWildcard(pattern) => {
            domain.is_some_and(|domain| wildcard_matches(pattern.as_bytes(), domain.as_bytes()))
        }
        RuleMatcher::DomainSuffix(suffix) => domain.is_some_and(|domain| {
            domain == suffix
                || domain
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }),
        RuleMatcher::IpCidr(cidr) => ip.is_some_and(|ip| cidr.contains(ip)),
        RuleMatcher::GeoIp(country) => ip.is_some_and(|ip| environment.geoip_matches(country, ip)),
        RuleMatcher::IpAsn(number) => ip.is_some_and(|ip| environment.ip_asn_matches(*number, ip)),
        RuleMatcher::RuleSet(name) => {
            environment.rule_set_matches(name, domain, ip)
                || environment
                    .rule_set_rules(name)
                    .iter()
                    .any(|rule| rule_matches(rule, input, environment))
        }
        RuleMatcher::GeoSite(category) => {
            domain.is_some_and(|domain| environment.geosite_matches(category, domain))
        }
        RuleMatcher::DstPort(start, end) => input
            .port
            .is_some_and(|port| (*start..=*end).contains(&port)),
        RuleMatcher::ProcessName(name) => input.process == Some(name.as_str()),
        RuleMatcher::SrcIp(cidr) => input
            .source
            .is_some_and(|source| cidr.contains(source.to_canonical())),
        RuleMatcher::SrcPort(start, end) => input
            .source_port
            .is_some_and(|port| (*start..=*end).contains(&port)),
        RuleMatcher::InPort(start, end) => input
            .in_port
            .is_some_and(|port| (*start..=*end).contains(&port)),
        RuleMatcher::HostnameType(kind) => {
            let found = match (domain, input.ip) {
                (Some(domain), _) if domain.contains('.') => Some(HostnameType::Domain),
                (Some(_), _) => Some(HostnameType::Simple),
                (None, Some(IpAddr::V4(_))) => Some(HostnameType::Ipv4),
                (None, Some(IpAddr::V6(address))) if address.to_ipv4_mapped().is_some() => {
                    Some(HostnameType::Ipv4)
                }
                (None, Some(IpAddr::V6(_))) => Some(HostnameType::Ipv6),
                (None, None) => None,
            };
            found == Some(*kind)
        }
        RuleMatcher::Subnet(condition) => environment
            .network()
            .is_some_and(|network| condition.matches(network)),
        RuleMatcher::DeviceName(name) => input.source.is_some_and(|source| {
            environment
                .device_name(source.to_canonical())
                .is_some_and(|found| found.trim().to_lowercase() == *name)
        }),
        RuleMatcher::CellularRadio(radio) => environment.network().is_some_and(|network| {
            network.kind == Some(NetworkKind::Cellular)
                && network
                    .radio
                    .as_deref()
                    .is_some_and(|found| found.eq_ignore_ascii_case(radio))
        }),
        RuleMatcher::Protocol(protocol) => {
            let port = input.port;
            if let Some(dns) = input.dns {
                // The engine's own DNS query: only DOH / DOQ say anything
                // about it beyond its transport.
                if matches!(protocol, RuleProtocol::Doh | RuleProtocol::Doq) {
                    return *protocol == dns;
                }
            }
            match (protocol, input.network) {
                (RuleProtocol::Tcp, Some(RouteNetwork::Tcp))
                | (RuleProtocol::Udp, Some(RouteNetwork::Udp)) => true,
                (RuleProtocol::Quic, Some(RouteNetwork::Udp))
                | (RuleProtocol::Https, Some(RouteNetwork::Tcp)) => port == Some(443),
                (RuleProtocol::Http, Some(RouteNetwork::Tcp)) => port == Some(80),
                (RuleProtocol::Stun, Some(RouteNetwork::Udp)) => port.is_some_and(is_stun_port),
                _ => false,
            }
        }
        RuleMatcher::UserAgent(pattern) => input
            .user_agent
            .is_some_and(|agent| wildcard_matches(pattern.as_bytes(), agent.as_bytes())),
        RuleMatcher::UrlRegex(pattern) => input.url.is_some_and(|url| pattern.is_match(url)),
        RuleMatcher::Script(name) => environment.script_matches(name) == Some(true),
        RuleMatcher::And(rules) => rules
            .iter()
            .all(|rule| rule_matches(rule, input, environment)),
        RuleMatcher::Or(rules) => rules
            .iter()
            .any(|rule| rule_matches(rule, input, environment)),
        RuleMatcher::Not(rule) => !rule_matches(rule, input, environment),
    }
}

fn select_group_member(
    group: &PolicyGroup,
    balance_key: Option<&str>,
    environment: &dyn RoutingEnvironment,
) -> PolicyTarget {
    let first = group.members[0].clone();
    match group.kind {
        PolicyGroupKind::Select => environment
            .selected_member(&group.id)
            .and_then(|name| {
                group
                    .members
                    .iter()
                    .find(|member| member.name() == name)
                    .cloned()
            })
            .or_else(|| group.default.clone())
            .unwrap_or(first),
        PolicyGroupKind::UrlTest => {
            let Some((best_latency, best)) = group
                .members
                .iter()
                .filter_map(|member| {
                    environment
                        .member_latency_ms(&group.id, member)
                        .map(|latency| (latency, member))
                })
                .min_by_key(|(latency, _)| *latency)
            else {
                return first;
            };
            let tolerance = group
                .health_check
                .as_ref()
                .map_or(0, |check| u32::from(check.tolerance_ms));
            let current = environment.url_test_current(&group.id).and_then(|name| {
                let member = group.members.iter().find(|member| member.name() == name)?;
                let latency = environment.member_latency_ms(&group.id, member)?;
                Some((latency, member))
            });
            match current {
                Some((latency, member)) if latency <= best_latency.saturating_add(tolerance) => {
                    member.clone()
                }
                _ => best.clone(),
            }
        }
        PolicyGroupKind::Subnet => environment
            .network()
            .and_then(|network| {
                group
                    .network_rules
                    .iter()
                    .find(|rule| rule.when.matches(network))
            })
            .map(|rule| rule.target.clone())
            .or_else(|| group.default.clone())
            .unwrap_or(first),
        PolicyGroupKind::Fallback => group
            .members
            .iter()
            .find(|member| environment.member_latency_ms(&group.id, member).is_some())
            .cloned()
            .unwrap_or(first),
        PolicyGroupKind::LoadBalance | PolicyGroupKind::RoundRobin => {
            // Members that passed their last check; every member until the
            // first checks finish or when all of them fail.
            let healthy: Vec<&PolicyTarget> = group
                .members
                .iter()
                .filter(|member| environment.member_latency_ms(&group.id, member).is_some())
                .collect();
            let candidates = if healthy.is_empty() {
                group.members.iter().collect()
            } else {
                healthy
            };
            let Some(key) = balance_key else {
                return candidates[0].clone();
            };
            if group.kind == PolicyGroupKind::RoundRobin {
                return candidates[environment.round_robin(&group.id) % candidates.len()].clone();
            }
            // Rendezvous hashing: a host moves only when its member goes away.
            candidates
                .into_iter()
                .max_by_key(|member| fnv1a(&[key.as_bytes(), b"\0", member.name().as_bytes()]))
                .cloned()
                .unwrap_or(first)
        }
    }
}

/// 64-bit FNV-1a over `parts`, stable across runs and platforms.
fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.iter().flat_map(|part| part.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

struct TargetNames<'a> {
    groups: BTreeSet<&'a str>,
    node_ids: &'a BTreeSet<String>,
}

impl<'a> TargetNames<'a> {
    fn collect(
        groups: &'a [PolicyGroupSpec],
        node_ids: &'a BTreeSet<String>,
    ) -> DomainResult<Self> {
        let mut names = BTreeSet::new();
        for group in groups {
            let id = group.id.trim();
            if id.is_empty() || id.contains(',') || is_reserved_name(id) {
                return Err(routing_error(
                    ROUTING_GROUP_ID_INVALID_CODE,
                    "policy group id must be non-empty, comma-free, and not DIRECT, FINAL, or a REJECT policy",
                ));
            }
            if node_ids.contains(id) || !names.insert(id) {
                return Err(routing_error(
                    ROUTING_GROUP_ID_CONFLICT_CODE,
                    format!("policy group id {id} duplicates another group or node id"),
                ));
            }
        }
        Ok(Self {
            groups: names,
            node_ids,
        })
    }

    fn resolve(&self, name: &str) -> DomainResult<PolicyTarget> {
        let name = name.trim();
        if name.eq_ignore_ascii_case(RESERVED_DIRECT) {
            Ok(PolicyTarget::Direct)
        } else if let Some(kind) = RejectKind::parse(name) {
            Ok(PolicyTarget::Reject(kind))
        } else if self.groups.contains(name) {
            Ok(PolicyTarget::Group(name.to_string()))
        } else if self.node_ids.contains(name) {
            Ok(PolicyTarget::Node(name.to_string()))
        } else {
            Err(routing_error(
                ROUTING_TARGET_UNKNOWN_CODE,
                format!("routing target {name} is not DIRECT, REJECT, REJECT-NO-DROP, REJECT-DROP, REJECT-TINYGIF, a policy group, or a node"),
            ))
        }
    }
}

fn normalize_group(spec: &PolicyGroupSpec, names: &TargetNames) -> DomainResult<PolicyGroup> {
    let id = spec.id.trim().to_string();
    let kind = match spec
        .kind
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .as_str()
    {
        "select" => PolicyGroupKind::Select,
        "url-test" | "urltest" => PolicyGroupKind::UrlTest,
        "fallback" => PolicyGroupKind::Fallback,
        "load-balance" | "loadbalance" => PolicyGroupKind::LoadBalance,
        "round-robin" | "roundrobin" => PolicyGroupKind::RoundRobin,
        "subnet" | "ssid" => PolicyGroupKind::Subnet,
        _ => {
            return Err(routing_error(
                ROUTING_GROUP_TYPE_UNSUPPORTED_CODE,
                format!(
                    "policy group {id} type must be select, url-test, fallback, load-balance, round-robin, or subnet"
                ),
            ))
        }
    };
    if kind == PolicyGroupKind::Subnet {
        return normalize_subnet_group(id, spec, names);
    }
    if !spec.network_rules.is_empty() {
        return Err(routing_error(
            ROUTING_GROUP_NETWORK_RULE_INVALID_CODE,
            format!("policy group {id} is not a subnet group and cannot have network rules"),
        ));
    }
    if spec.members.is_empty() {
        return Err(routing_error(
            ROUTING_GROUP_MEMBERS_EMPTY_CODE,
            format!("policy group {id} must have at least one member"),
        ));
    }

    let mut members = Vec::with_capacity(spec.members.len());
    // A set beside the list, so a large group dedupes in linear time.
    let mut seen = BTreeSet::new();
    for member in &spec.members {
        let member = names.resolve(member)?;
        check_member_supported(&id, kind, &member)?;
        if seen.insert(member.clone()) {
            members.push(member);
        }
    }

    let default = match (&spec.default, kind) {
        (None, _) => None,
        (Some(name), PolicyGroupKind::Select) => {
            let target = names.resolve(name)?;
            if !members.contains(&target) {
                return Err(routing_error(
                    ROUTING_GROUP_DEFAULT_INVALID_CODE,
                    format!("policy group {id} default must be one of its members"),
                ));
            }
            Some(target)
        }
        (Some(_), _) => {
            return Err(routing_error(
                ROUTING_GROUP_DEFAULT_INVALID_CODE,
                format!("policy group {id} default is only supported for select groups"),
            ))
        }
    };

    let health_check = match kind {
        PolicyGroupKind::Select => {
            if spec.url.is_some() || spec.interval_secs.is_some() || spec.tolerance_ms.is_some() {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!("policy group {id} is select and cannot have health check fields"),
                ));
            }
            None
        }
        PolicyGroupKind::Subnet => unreachable!("subnet groups return above"),
        PolicyGroupKind::UrlTest
        | PolicyGroupKind::Fallback
        | PolicyGroupKind::LoadBalance
        | PolicyGroupKind::RoundRobin => {
            if kind != PolicyGroupKind::UrlTest && spec.tolerance_ms.is_some() {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!(
                        "policy group {id} is {} and cannot have a tolerance",
                        kind.as_str()
                    ),
                ));
            }
            let url = spec
                .url
                .as_deref()
                .map(str::trim)
                .unwrap_or(DEFAULT_HEALTH_CHECK_URL)
                .to_string();
            let interval_secs = spec
                .interval_secs
                .unwrap_or(DEFAULT_HEALTH_CHECK_INTERVAL_SECS);
            if !(url.starts_with("http://") || url.starts_with("https://")) || interval_secs == 0 {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!(
                        "policy group {id} health check needs an http(s) url and a positive interval"
                    ),
                ));
            }
            Some(HealthCheck {
                url,
                interval_secs,
                tolerance_ms: spec.tolerance_ms.unwrap_or(DEFAULT_URL_TEST_TOLERANCE_MS),
            })
        }
    };

    if spec.evaluate_before_use && !kind.is_health_checked() {
        return Err(routing_error(
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
            format!(
                "policy group {id} is {} and cannot evaluate before use",
                kind.as_str()
            ),
        ));
    }

    Ok(PolicyGroup {
        id,
        kind,
        members,
        default,
        health_check,
        evaluate_before_use: spec.evaluate_before_use,
        network_rules: Vec::new(),
    })
}

/// Groups never contain REJECT; only select and subnet groups contain other
/// groups.
fn check_member_supported(
    id: &str,
    kind: PolicyGroupKind,
    member: &PolicyTarget,
) -> DomainResult<()> {
    let supported = match (member, kind) {
        (PolicyTarget::Reject(_), _) => false,
        (PolicyTarget::Group(_), PolicyGroupKind::Select | PolicyGroupKind::Subnet) => true,
        (PolicyTarget::Group(_), _) => false,
        (PolicyTarget::Direct | PolicyTarget::Node(_), _) => true,
    };
    if supported {
        Ok(())
    } else {
        Err(routing_error(
            ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE,
            format!(
                "policy group {id} cannot contain {}; groups never contain REJECT and only select and subnet groups contain other groups",
                member.name()
            ),
        ))
    }
}

/// A subnet group: a required default, network rules in order, no members
/// of its own (they are the default and the rule targets) and no health
/// check.
fn normalize_subnet_group(
    id: String,
    spec: &PolicyGroupSpec,
    names: &TargetNames,
) -> DomainResult<PolicyGroup> {
    let invalid = |message: String| routing_error(ROUTING_GROUP_NETWORK_RULE_INVALID_CODE, message);
    if !spec.members.is_empty() {
        return Err(invalid(format!(
            "subnet group {id} takes its members from its network rules and default"
        )));
    }
    if spec.url.is_some()
        || spec.interval_secs.is_some()
        || spec.tolerance_ms.is_some()
        || spec.evaluate_before_use
    {
        return Err(routing_error(
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
            format!("policy group {id} is subnet and cannot have health check fields"),
        ));
    }
    let Some(default) = spec.default.as_deref() else {
        return Err(routing_error(
            ROUTING_GROUP_DEFAULT_INVALID_CODE,
            format!("subnet group {id} needs a default"),
        ));
    };
    let default = names.resolve(default)?;
    check_member_supported(&id, PolicyGroupKind::Subnet, &default)?;
    let mut members = vec![default.clone()];
    let mut seen = BTreeSet::from([default.clone()]);
    let mut network_rules = Vec::with_capacity(spec.network_rules.len());
    for (index, rule) in spec.network_rules.iter().enumerate() {
        let when = NetworkCondition::parse(&rule.when).ok_or_else(|| {
            invalid(format!(
                "subnet group {id} network rule {index} must be SSID:, BSSID:, ROUTER:, SUBNET:, TYPE: or CELLULAR"
            ))
        })?;
        let target = names.resolve(&rule.target)?;
        check_member_supported(&id, PolicyGroupKind::Subnet, &target)?;
        if seen.insert(target.clone()) {
            members.push(target.clone());
        }
        network_rules.push(NetworkRule { when, target });
    }
    Ok(PolicyGroup {
        id,
        kind: PolicyGroupKind::Subnet,
        members,
        default: Some(default),
        health_check: None,
        evaluate_before_use: false,
        network_rules,
    })
}

fn reject_group_cycles(groups: &[PolicyGroup]) -> DomainResult<()> {
    let edges = groups
        .iter()
        .map(|group| {
            let children = group
                .members
                .iter()
                .filter_map(|member| match member {
                    PolicyTarget::Group(id) => Some(id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (group.id.as_str(), children)
        })
        .collect::<BTreeMap<_, _>>();

    // 0 = unvisited, 1 = on the current path, 2 = done. Depth-first with
    // an explicit stack of (group, next child), so a long chain of groups
    // cannot overflow the thread's stack.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    for root in edges.keys().copied() {
        if state.get(root).copied().unwrap_or(0) != 0 {
            continue;
        }
        state.insert(root, 1);
        let mut stack: Vec<(&str, usize)> = vec![(root, 0)];
        while let Some(&(id, next)) = stack.last() {
            let child = edges
                .get(id)
                .and_then(|children| children.get(next))
                .copied();
            let Some(child) = child else {
                state.insert(id, 2);
                stack.pop();
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            match state.get(child).copied().unwrap_or(0) {
                1 => {
                    return Err(routing_error(
                        ROUTING_GROUP_CYCLE_CODE,
                        format!("policy group {child} is part of a group cycle"),
                    ))
                }
                2 => {}
                _ => {
                    state.insert(child, 1);
                    stack.push((child, 0));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn normalize_rule_domain(value: &str) -> DomainResult<String> {
    let domain = normalize_query_domain(value);
    let valid = !domain.is_empty()
        && domain
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
        && !domain.starts_with('.')
        && !domain.contains("..");
    if valid {
        Ok(domain)
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "domain rule value must be an ASCII domain name",
        ))
    }
}

/// A `DOMAIN-WILDCARD` value: host characters plus `*` and `?`, with at
/// least one literal character.
fn normalize_domain_wildcard(value: &str) -> DomainResult<String> {
    let pattern = normalize_query_domain(value);
    let valid = pattern
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._*?".contains(character))
        && pattern
            .chars()
            .any(|character| character.is_ascii_alphanumeric());
    if valid {
        Ok(pattern)
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "DOMAIN-WILDCARD rule value must be a domain with * and ? wildcards",
        ))
    }
}

/// Glob match where `*` is any run (dots included) and `?` one byte.
fn wildcard_matches(pattern: &[u8], text: &[u8]) -> bool {
    // The literal runs before the first and after the last wildcard are
    // anchored: a cheap reject for most texts before the backtracking walk.
    let is_wild = |b: &u8| *b == b'*' || *b == b'?';
    let head = pattern.iter().position(is_wild).unwrap_or(pattern.len());
    let tail = pattern.iter().rposition(is_wild).map_or(0, |last| last + 1);
    if !text.starts_with(&pattern[..head]) || !text.ends_with(&pattern[tail..]) {
        return false;
    }
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

fn normalize_query_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// An `IP-ASN` value: a decimal AS number from 1, with or without `AS`.
fn parse_asn(value: &str) -> DomainResult<u32> {
    let value = value.trim();
    let digits = value
        .strip_prefix("AS")
        .or_else(|| value.strip_prefix("as"))
        .or_else(|| value.strip_prefix("As"))
        .unwrap_or(value);
    match digits.parse::<u32>() {
        Ok(number) if number > 0 && digits.bytes().all(|byte| byte.is_ascii_digit()) => Ok(number),
        _ => Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "IP-ASN rule value must be an AS number such as 13335",
        )),
    }
}

fn normalize_country_code(value: &str) -> DomainResult<String> {
    if value.len() == 2
        && value
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        Ok(value.to_ascii_uppercase())
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "GEOIP rule value must be a two-letter country code",
        ))
    }
}

/// DIRECT, FINAL and every REJECT policy name, `REJECT-IMG` included.
fn is_reserved_name(name: &str) -> bool {
    RESERVED_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
        || RejectKind::parse(name).is_some()
}

fn with_rule_index(error: DomainError, index: usize) -> DomainError {
    DomainError::new(
        error.code,
        format!("routing rule {index}: {}", error.message),
    )
}

pub(crate) fn routing_error(code: &'static str, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}
