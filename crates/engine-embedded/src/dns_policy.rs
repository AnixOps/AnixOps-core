//! Which upstream answers a DNS name: the `dns` section's hosts, per-domain
//! rules and servers.
//!
//! A query is answered locally when its name is in `hosts` (exact, or a
//! subdomain of a `*.` entry). Otherwise the first rule whose domains, suffixes,
//! keywords or rule set match picks the servers, and names no rule picks go to
//! the default servers. Several servers named together are raced (see
//! [`crate::dns_client`]), and the `fallback` servers are asked when they
//! fail. Each server is reached through the proxy (the config's outbound, or
//! the node a rule picks and else the global target, never DIRECT by a rule;
//! the direct outbound in the direct mode) or directly; `system` servers are
//! always direct. A config without `servers` keeps the single `upstream` over
//! TCP through the proxy.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::TargetAddr;
use serde::Serialize;

use crate::config::{DnsConfig, DnsRuleConfig, DnsServerRef, DnsVia};
use crate::dns::{self, Upstream, UpstreamError};
use crate::rule_sets::RuleSetStore;

pub const MAX_DNS_SERVERS: usize = 16;
pub const MAX_DNS_RULES: usize = 64;
/// Domains, suffixes and keywords over every rule.
pub const MAX_DNS_RULE_DOMAINS: usize = 4096;
pub const MAX_HOSTS: usize = 1024;
pub const MAX_HOST_ADDRESSES: usize = 8;
/// Servers raced for one name.
pub const MAX_RACE: usize = 4;
/// Addresses in `system_servers`.
pub const MAX_SYSTEM_SERVERS: usize = 8;

/// One configured upstream.
#[derive(Clone)]
pub struct DnsServer {
    pub name: String,
    pub upstream: Upstream,
    pub via: DnsVia,
}

/// What to do with one query.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Reply with this message without asking anyone.
    Local(Vec<u8>),
    /// Forward to the servers of this target ([`DnsPolicy::target`]).
    Forward(usize),
}

/// One server as the client's DNS page shows it; no URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsServerView {
    pub name: String,
    /// `tcp`, `udp`, `tls`, `https`, `quic` or `system`.
    pub scheme: &'static str,
    /// `proxy` or `direct`.
    pub via: &'static str,
    /// Among the servers for names no rule picks.
    pub default: bool,
    /// Among the fallback servers.
    pub fallback: bool,
}

struct DnsRule {
    domains: HashSet<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    rule_set: Option<String>,
    target: usize,
}

impl DnsRule {
    fn matches(&self, name: &str, rule_sets: Option<&RuleSetStore>) -> bool {
        self.domains.contains(name)
            || self.suffixes.iter().any(|suffix| is_within(name, suffix))
            || self
                .keywords
                .iter()
                .any(|keyword| name.contains(keyword.as_str()))
            || self.rule_set.as_ref().is_some_and(|set| {
                rule_sets.is_some_and(|store| {
                    store
                        .read()
                        .get(set)
                        .is_some_and(|set| set.matches(Some(name), None))
                })
            })
    }
}

pub struct DnsPolicy {
    servers: Vec<DnsServer>,
    /// Sets of servers asked together, each sorted and distinct.
    targets: Vec<Vec<usize>>,
    default: usize,
    fallback: Option<usize>,
    hosts: HashMap<String, Vec<IpAddr>>,
    /// `*.suffix` hosts, by suffix.
    wildcard_hosts: Vec<(String, Vec<IpAddr>)>,
    rules: Vec<DnsRule>,
    timeout: Duration,
}

impl fmt::Debug for DnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsPolicy")
            .field("servers", &self.servers.len())
            .field("hosts", &(self.hosts.len() + self.wildcard_hosts.len()))
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl DnsPolicy {
    /// Every query to `upstream` over TCP through the proxy.
    pub fn tcp(upstream: SocketAddr, timeout: Duration) -> Self {
        Self {
            servers: vec![DnsServer {
                name: "default".to_string(),
                upstream: Upstream::Tcp(TargetAddr::Ip(upstream)),
                via: DnsVia::Proxy,
            }],
            targets: vec![vec![0]],
            default: 0,
            fallback: None,
            hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            rules: Vec::new(),
            timeout,
        }
    }

    /// The policy of a `dns` section, or why it is refused (a fixed message
    /// without names or URLs).
    pub fn from_config(config: &DnsConfig) -> Result<Self, &'static str> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let system = system_servers(&config.system_servers)?;
        let mut policy = if config.servers.is_empty() {
            if config.default.is_some() || config.fallback.is_some() || !config.rules.is_empty() {
                return Err("dns rules, default and fallback need servers");
            }
            Self::tcp(config.upstream, timeout)
        } else {
            if config.servers.len() > MAX_DNS_SERVERS {
                return Err("dns has too many servers");
            }
            let mut servers: Vec<DnsServer> = Vec::with_capacity(config.servers.len());
            for server in &config.servers {
                if !crate::config::is_identifier(&server.name) {
                    return Err("dns server names must be 1-128 characters of [A-Za-z0-9._-]");
                }
                if servers.iter().any(|known| known.name == server.name) {
                    return Err("dns server names must be unique");
                }
                let mut upstream = Upstream::parse(&server.url, server.server_name.as_deref())
                    .map_err(|error| match error {
                        UpstreamError::Invalid => "dns server url is invalid",
                        UpstreamError::Unsupported => {
                            "dns over tls, https and quic need the dns-tls / dns-quic features"
                        }
                    })?;
                let mut via = server.via;
                if let Upstream::System(_) = upstream {
                    upstream = Upstream::System(system.clone());
                    via = DnsVia::Direct;
                }
                servers.push(DnsServer {
                    name: server.name.clone(),
                    upstream,
                    via,
                });
            }
            let mut targets = Targets::new(&servers);
            let default = match &config.default {
                Some(reference) => targets.of(reference, "dns default names no server")?,
                None => targets.of(&DnsServerRef::One(servers[0].name.clone()), "")?,
            };
            let fallback = config
                .fallback
                .as_ref()
                .map(|reference| targets.of(reference, "dns fallback names no server"))
                .transpose()?;
            if config.rules.len() > MAX_DNS_RULES {
                return Err("dns has too many rules");
            }
            let domains: usize = config.rules.iter().map(DnsRuleConfig::entry_count).sum();
            if domains > MAX_DNS_RULE_DOMAINS {
                return Err("dns rules have too many domains");
            }
            let mut rules = Vec::with_capacity(config.rules.len());
            for rule in &config.rules {
                let target = targets.of(&rule.server, "dns rule names no server")?;
                if rule.entry_count() == 0 && rule.rule_set.is_none() {
                    return Err("dns rule matches nothing");
                }
                rules.push(DnsRule {
                    domains: names(&rule.domain)?.into_iter().collect(),
                    suffixes: names(&rule.domain_suffix)?,
                    keywords: rule
                        .domain_keyword
                        .iter()
                        .map(|keyword| keyword.trim().to_ascii_lowercase())
                        .filter(|keyword| !keyword.is_empty())
                        .collect(),
                    rule_set: rule.rule_set.clone(),
                    target,
                });
            }
            let sets = targets.sets;
            Self {
                servers,
                targets: sets,
                default,
                fallback,
                hosts: HashMap::new(),
                wildcard_hosts: Vec::new(),
                rules,
                timeout,
            }
        };
        policy.set_hosts(&config.hosts)?;
        Ok(policy)
    }

    fn set_hosts(&mut self, hosts: &BTreeMap<String, Vec<IpAddr>>) -> Result<(), &'static str> {
        if hosts.len() > MAX_HOSTS {
            return Err("dns has too many hosts");
        }
        for (name, addresses) in hosts {
            if addresses.is_empty() || addresses.len() > MAX_HOST_ADDRESSES {
                return Err("dns hosts need 1-8 addresses each");
            }
            match name.strip_prefix("*.") {
                Some(suffix) => self
                    .wildcard_hosts
                    .push((normalize(suffix)?, addresses.clone())),
                None => {
                    self.hosts.insert(normalize(name)?, addresses.clone());
                }
            }
        }
        Ok(())
    }

    pub fn servers(&self) -> &[DnsServer] {
        &self.servers
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The indexes in [`DnsPolicy::servers`] of the servers asked together
    /// for `target`.
    pub fn target(&self, target: usize) -> &[usize] {
        &self.targets[target]
    }

    /// The target asked when the chosen one fails.
    pub fn fallback(&self) -> Option<usize> {
        self.fallback
    }

    /// The servers without their URLs, for status.
    pub fn view(&self) -> Vec<DnsServerView> {
        self.servers
            .iter()
            .enumerate()
            .map(|(index, server)| DnsServerView {
                name: server.name.clone(),
                scheme: server.upstream.scheme(),
                via: server.via.as_str(),
                default: self.targets[self.default].contains(&index),
                fallback: self
                    .fallback
                    .is_some_and(|fallback| self.targets[fallback].contains(&index)),
            })
            .collect()
    }

    /// Decides how to answer `query`. A query whose question does not parse
    /// goes to the default server unchanged.
    pub fn plan(&self, query: &[u8], rule_sets: Option<&RuleSetStore>) -> Plan {
        let Some(question) = dns::question(query) else {
            return Plan::Forward(self.default);
        };
        if let Some(addresses) = self.host(&question.name) {
            return Plan::Local(dns::local_answer(query, &question, addresses));
        }
        Plan::Forward(self.server_for(&question.name, rule_sets))
    }

    /// The target (servers asked together) for `name`.
    pub fn server_for(&self, name: &str, rule_sets: Option<&RuleSetStore>) -> usize {
        self.rules
            .iter()
            .find(|rule| rule.matches(name, rule_sets))
            .map_or(self.default, |rule| rule.target)
    }

    fn host(&self, name: &str) -> Option<&[IpAddr]> {
        if let Some(addresses) = self.hosts.get(name) {
            return Some(addresses);
        }
        self.wildcard_hosts
            .iter()
            .find(|(suffix, _)| name.len() > suffix.len() && is_within(name, suffix))
            .map(|(_, addresses)| addresses.as_slice())
    }
}

/// The distinct server sets the default, the rules and the fallback name.
struct Targets<'a> {
    servers: &'a [DnsServer],
    sets: Vec<Vec<usize>>,
}

impl<'a> Targets<'a> {
    fn new(servers: &'a [DnsServer]) -> Self {
        Self {
            servers,
            sets: Vec::new(),
        }
    }

    /// The target of `reference`, added when new; `unknown` is the error for
    /// a name that is not a server.
    fn of(
        &mut self,
        reference: &DnsServerRef,
        unknown: &'static str,
    ) -> Result<usize, &'static str> {
        let names = reference.names();
        if names.is_empty() || names.len() > MAX_RACE {
            return Err("dns server lists race 1-4 servers");
        }
        let mut set = Vec::with_capacity(names.len());
        for name in names {
            let index = self
                .servers
                .iter()
                .position(|server| server.name == *name)
                .ok_or(unknown)?;
            if set.contains(&index) {
                return Err("dns server lists must not repeat a server");
            }
            set.push(index);
        }
        set.sort_unstable();
        Ok(match self.sets.iter().position(|known| *known == set) {
            Some(target) => target,
            None => {
                self.sets.push(set);
                self.sets.len() - 1
            }
        })
    }
}

/// The `system_servers` addresses: `ip` or `ip:port` / `[ipv6]:port`, port
/// 53 by default.
fn system_servers(list: &[String]) -> Result<Arc<[SocketAddr]>, &'static str> {
    if list.len() > MAX_SYSTEM_SERVERS {
        return Err("dns has too many system servers");
    }
    let mut servers: Vec<SocketAddr> = Vec::with_capacity(list.len());
    for entry in list {
        let entry = entry.trim();
        let address = match entry.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, 53),
            Err(_) => entry
                .parse::<SocketAddr>()
                .ok()
                .filter(|address| address.port() != 0)
                .ok_or("dns system server is not an address")?,
        };
        if address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err("dns system server is not an address");
        }
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    Ok(Arc::from(servers))
}

/// Whether `name` is `suffix` or one of its subdomains.
fn is_within(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// A configured name in lower case without a leading `.`/`+.` or final dot.
fn normalize(name: &str) -> Result<String, &'static str> {
    let name = name.trim();
    let name = name
        .strip_prefix("+.")
        .or_else(|| name.strip_prefix('.'))
        .unwrap_or(name);
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("dns domain is invalid");
    }
    Ok(name)
}

fn names(list: &[String]) -> Result<Vec<String>, &'static str> {
    list.iter().map(|name| normalize(name)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsServerConfig;

    fn query(name: &[u8]) -> Vec<u8> {
        let mut query = vec![0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        query
    }

    fn server(name: &str, url: &str, via: DnsVia) -> DnsServerConfig {
        DnsServerConfig {
            name: name.to_string(),
            url: url.to_string(),
            server_name: None,
            via,
        }
    }

    fn config() -> DnsConfig {
        DnsConfig {
            servers: vec![
                server("remote", "tcp://8.8.8.8", DnsVia::Proxy),
                server("local", "223.5.5.5:53", DnsVia::Direct),
            ],
            hosts: BTreeMap::from([
                (
                    "router.lan".to_string(),
                    vec!["192.168.1.1".parse().unwrap()],
                ),
                (
                    "*.corp.example".to_string(),
                    vec!["10.0.0.1".parse().unwrap()],
                ),
            ]),
            rules: vec![
                DnsRuleConfig {
                    domain_suffix: vec!["cn".into(), "+.Baidu.com".into()],
                    server: "local".into(),
                    ..DnsRuleConfig::default()
                },
                DnsRuleConfig {
                    domain_keyword: vec!["taobao".into()],
                    server: "local".into(),
                    ..DnsRuleConfig::default()
                },
            ],
            ..DnsConfig::default()
        }
    }

    #[test]
    fn names_pick_their_server() {
        let policy = DnsPolicy::from_config(&config()).unwrap();
        assert_eq!(policy.server_for("www.baidu.com", None), 1);
        assert_eq!(policy.server_for("baidu.com", None), 1);
        assert_eq!(policy.server_for("notbaidu.com", None), 0);
        assert_eq!(policy.server_for("gov.cn", None), 1);
        assert_eq!(policy.server_for("world.taobao.com", None), 1);
        assert_eq!(policy.server_for("example.com", None), 0);
        assert_eq!(
            policy.plan(&query(b"\x03www\x05baidu\x03com\x00"), None),
            Plan::Forward(1)
        );
        assert_eq!(policy.plan(b"not dns", None), Plan::Forward(0));
        let views = policy.view();
        assert_eq!(views[1].via, "direct");
        assert_eq!(views[1].scheme, "tcp");
        assert!(views[0].default);
    }

    #[test]
    fn hosts_are_answered_locally() {
        let policy = DnsPolicy::from_config(&config()).unwrap();
        let Plan::Local(answer) = policy.plan(&query(b"\x06Router\x03lan\x00"), None) else {
            panic!("hosts entry should answer locally");
        };
        assert!(answer.ends_with(&[192, 168, 1, 1]));
        let Plan::Local(answer) = policy.plan(&query(b"\x03git\x04corp\x07example\x00"), None)
        else {
            panic!("wildcard hosts entry should answer locally");
        };
        assert!(answer.ends_with(&[10, 0, 0, 1]));
        // The wildcard covers subdomains only.
        assert_eq!(
            policy.plan(&query(b"\x04corp\x07example\x00"), None),
            Plan::Forward(0)
        );
    }

    #[test]
    fn rule_sets_back_dns_rules() {
        use config_core::rule_set::{BareDomain, RuleSet, RuleSetEntries};

        let mut config = config();
        config.rules = vec![DnsRuleConfig {
            rule_set: Some("geosite-cn".into()),
            server: "local".into(),
            ..DnsRuleConfig::default()
        }];
        let policy = DnsPolicy::from_config(&config).unwrap();
        let (entries, _) = RuleSetEntries::parse_list("qq.com\n", BareDomain::Suffix);
        let store = RuleSetStore::new(
            BTreeMap::from([(
                "geosite-cn".to_string(),
                RuleSet::from_entries(&entries).unwrap(),
            )]),
            Vec::new(),
        );
        assert_eq!(policy.server_for("im.qq.com", Some(&store)), 1);
        assert_eq!(policy.server_for("im.qq.com", None), 0);
        assert_eq!(policy.server_for("example.com", Some(&store)), 0);
    }

    #[test]
    fn bad_sections_are_refused() {
        let legacy = DnsPolicy::from_config(&DnsConfig::default()).unwrap();
        assert_eq!(legacy.servers().len(), 1);

        let mut unknown = config();
        unknown.rules[0].server = "nowhere".into();
        let mut duplicate = config();
        duplicate.servers[1].name = "remote".into();
        let mut bad_url = config();
        bad_url.servers[0].url = "ftp://8.8.8.8".into();
        let mut empty_rule = config();
        empty_rule.rules.push(DnsRuleConfig {
            server: "local".into(),
            ..DnsRuleConfig::default()
        });
        let mut bad_host = config();
        bad_host
            .hosts
            .insert("a b".into(), vec!["1.1.1.1".parse().unwrap()]);
        let mut no_address = config();
        no_address.hosts.insert("x.lan".into(), Vec::new());
        let mut rules_without_servers = config();
        rules_without_servers.servers.clear();
        for config in [
            unknown,
            duplicate,
            bad_url,
            empty_rule,
            bad_host,
            no_address,
            rules_without_servers,
        ] {
            assert!(DnsPolicy::from_config(&config).is_err());
        }
    }
}
