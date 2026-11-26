//! Intranet names (requirement R28, spec §15.9.2): the network config's
//! `dns` section, the name list built from it and from the members' own
//! host names, and the answers to queries for it.
//!
//! Both entrances use [`Names::answer`]: the engine's split DNS hands it the
//! queries for the suffix, and a full node answers queries sent to the
//! network's resolver address on its virtual interface ([`intercept`]).
//! Nothing here sends a query to the network.
//!
//! - [`normalize`]: the name rule and its Unicode 15.1.0 table.
//! - [`message`]: reading a query and writing the answer.
//! - [`intercept`]: the resolver address on the virtual interface.
//! - [`reverse`]: the reverse zones worked out from the network's ranges.

pub mod intercept;
pub mod message;
pub mod normalize;
pub mod reverse;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::net::IpNet;
use crate::scope::is_intranet_address;
use message::{Query, Rcode, Record, Transport};
pub use normalize::{is_normalized, normalize_label};
use reverse::ReverseZones;

/// Default suffix (spec §15.9.2 item 1).
pub const DEFAULT_SUFFIX: &str = "mesh.internal";
/// Longest suffix: a full name `<63-byte name>.<16-byte region>.<suffix>`
/// stays within 253 bytes.
pub const MAX_SUFFIX_BYTES: usize = 172;
/// Most entries in `dns.names`; more refuse the whole config.
pub const MAX_NAMES: usize = 4096;
/// Most addresses one name answers per record type; past that the answer
/// has the first ones and, over UDP, the TC bit.
pub const MAX_ANSWER_ADDRESSES: usize = 32;
/// Time to live of every answer, in seconds (spec §15.9.2 item 2).
pub const TTL_SECONDS: u32 = 5;
/// The status shows at most this many bytes of a refused entry's name.
const MAX_REFUSED_TEXT: usize = 128;

/// The `dns` section of a network config (`docs/architecture/mesh-module.md`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Absent: [`DEFAULT_SUFFIX`].
    #[serde(default)]
    pub suffix: Option<String>,
    /// This network's region code, the second label of its members' full
    /// names. Absent: the region of the `names` entry for this node's own
    /// address, if there is one.
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub names: Vec<NameConfig>,
    /// The fixed resolver address on the virtual interface (spec §15.9.2
    /// item 8); needs the capability `mesh_resolver_address`.
    #[serde(default)]
    pub resolver_address: Option<String>,
}

/// One entry of `dns.names`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameConfig {
    /// `<name>.<region code>`, both labels already normalized.
    pub name: String,
    pub address: String,
}

/// Why an entry of `dns.names` was skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedReason {
    /// The address is not an intranet address (spec §15.4), or not an
    /// address at all.
    NotIntranet,
    /// The name is not `<name>.<region code>` of two normalized labels.
    InvalidName,
}

/// One skipped entry, as the status lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RefusedName {
    pub name: String,
    pub address: String,
    pub reason: RefusedReason,
}

/// One accepted entry of `dns.names`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredName {
    pub label: String,
    pub region: String,
    pub address: IpAddr,
}

/// The validated `dns` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsSettings {
    pub enabled: bool,
    /// Lower case, without the final dot.
    pub suffix: String,
    pub region: Option<String>,
    /// Accepted entries, in config order.
    pub names: Vec<ConfiguredName>,
    /// Skipped entries, in config order.
    pub refused: Vec<RefusedName>,
    pub resolver_address: Option<IpAddr>,
}

impl Default for DnsSettings {
    /// What a network without a `dns` section has: names off.
    fn default() -> Self {
        Self {
            enabled: false,
            suffix: DEFAULT_SUFFIX.into(),
            region: None,
            names: Vec::new(),
            refused: Vec::new(),
            resolver_address: None,
        }
    }
}

/// The suffix the intranet names are under (spec §15.9.2 item 1), or
/// `None` when `suffix` may not carry them. Compared without a final dot
/// and in lower case: it must lie under `internal` with at least two
/// labels (so the root, any single label, `arpa`, `home.arpa`, the reverse
/// zones and `local` are all refused), at most [`MAX_SUFFIX_BYTES`] bytes,
/// each label 1 to 63 bytes of ASCII letters, digits and inner hyphens
/// (anything else, non-ASCII included, is refused). The reverse
/// zones are worked out from the virtual subnets, never configured. The
/// same rule applies to the local override (`mesh_set_dns`).
pub fn normalize_suffix(suffix: &str) -> Option<String> {
    let suffix = suffix
        .strip_suffix('.')
        .unwrap_or(suffix)
        .to_ascii_lowercase();
    let labels: Vec<&str> = suffix.split('.').collect();
    let labels_ok = labels.iter().all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    let under_internal = labels.len() >= 2 && labels.last() == Some(&"internal");
    (suffix.len() <= MAX_SUFFIX_BYTES && labels_ok && under_internal).then_some(suffix)
}

/// Cuts `text` to at most `max` bytes on a character boundary.
fn clip(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

impl DnsConfig {
    /// Checks the section of a network whose virtual subnets are
    /// `virtual_subnets`. A bad suffix, region or resolver address, or too
    /// many names, refuses the whole config; a bad entry is skipped and
    /// listed.
    pub fn validate(self, virtual_subnets: &[IpNet]) -> Result<DnsSettings, &'static str> {
        let suffix = self.suffix.as_deref().unwrap_or(DEFAULT_SUFFIX);
        let Some(suffix) = normalize_suffix(suffix) else {
            return Err("mesh dns suffix must be a name under internal");
        };
        if let Some(region) = &self.region {
            if !is_normalized(region) {
                return Err("mesh dns region is not a normalized label");
            }
        }
        if self.names.len() > MAX_NAMES {
            return Err("mesh dns lists too many names");
        }
        // With the section off the resolver address is ignored, unchecked:
        // nothing is intercepted or answered at all (spec §15.9.2).
        let resolver_address = match &self.resolver_address {
            _ if !self.enabled => None,
            None => None,
            Some(text) => {
                let address: IpAddr = text
                    .trim()
                    .parse()
                    .map_err(|_| "mesh dns resolver_address is not an address")?;
                if !virtual_subnets.iter().any(|net| net.is_host(address)) {
                    return Err("mesh dns resolver_address is outside the virtual subnet");
                }
                Some(address)
            }
        };
        let mut names = Vec::with_capacity(self.names.len());
        let mut refused = Vec::new();
        for entry in self.names {
            let refuse = |reason| RefusedName {
                name: clip(&entry.name, MAX_REFUSED_TEXT),
                address: clip(&entry.address, MAX_REFUSED_TEXT),
                reason,
            };
            let parts: Vec<&str> = entry.name.split('.').collect();
            let &[label, region] = parts.as_slice() else {
                refused.push(refuse(RefusedReason::InvalidName));
                continue;
            };
            if !is_normalized(label) || !is_normalized(region) {
                refused.push(refuse(RefusedReason::InvalidName));
                continue;
            }
            let address = match entry.address.trim().parse::<IpAddr>() {
                Ok(address) if is_intranet_address(address) && !is_mapped(address) => address,
                _ => {
                    refused.push(refuse(RefusedReason::NotIntranet));
                    continue;
                }
            };
            names.push(ConfiguredName {
                label: label.to_owned(),
                region: region.to_owned(),
                address,
            });
        }
        Ok(DnsSettings {
            enabled: self.enabled,
            suffix,
            region: self.region,
            names,
            refused,
            resolver_address,
        })
    }
}

/// IPv4-mapped IPv6 addresses have the IPv4 spelling; refusing them keeps
/// one address one record type.
fn is_mapped(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

/// Where a name comes from, as the status shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// `dns.names`, from the panel.
    Panel,
    /// A member's own host name from its route information (spec §12.3
    /// field 6): any member can claim any name.
    Member,
}

/// One name of the list, per source (`names[]` of the status).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NameStatus {
    /// `<name>.<region code>`, or `<name>` while this network's region is
    /// unknown; without the suffix.
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub source: NameSource,
    /// The name stands for more than one member or entry; queries get all
    /// their addresses, the panel's first.
    pub duplicate: bool,
    /// `false` when an address lies outside the ranges answers may point to
    /// and is not answered (spec §15.9.2 item 9).
    pub answerable: bool,
}

/// One reachable member as the name list needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberNames {
    /// Its host name as it announced it, not yet normalized.
    pub hostname: Option<String>,
    /// Its virtual addresses, as accepted.
    pub addresses: Vec<IpAddr>,
    /// The subnets it advertises, as accepted.
    pub subnets: Vec<IpNet>,
}

/// The network around the name list.
pub struct NetworkView<'a> {
    pub virtual_subnets: &'a [IpNet],
    /// The ranges of the network's host groups (spec §15.7): names in
    /// them are answered like names in the virtual subnets.
    pub host_groups: &'a [IpNet],
    /// This node's virtual addresses.
    pub local_addresses: &'a [IpAddr],
    /// This node's host name, when the config or the system gives one.
    pub own_hostname: Option<&'a str>,
    /// The other reachable members.
    pub members: &'a [MemberNames],
}

/// What [`Names::answer`] did with a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The answer to send back.
    Answer(Vec<u8>),
    /// Not a query for the intranet names: the caller's other resolvers
    /// take it.
    NotOurs,
}

type Key = (String, Option<String>);

/// The name list of one network and the answers to queries for it. Built
/// again whenever the members change; immutable once built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    enabled: bool,
    suffix: String,
    suffix_labels: Vec<Vec<u8>>,
    /// This network's region code, when known.
    region: Option<String>,
    /// Region codes that have names.
    regions: BTreeSet<String>,
    /// Answerable addresses by name and region, the panel's first.
    by_name: BTreeMap<Key, Vec<IpAddr>>,
    /// Full names (without the suffix) by answerable address, for PTR.
    by_address: BTreeMap<IpAddr, Vec<String>>,
    /// Ranges answers may concern (spec §15.9.2 item 9).
    scope: Vec<IpNet>,
    /// The only reverse names answered (spec §15.9.2 items 1 and 7).
    reverse: ReverseZones,
    entries: Vec<NameStatus>,
    refused: Vec<RefusedName>,
    resolver_address: Option<IpAddr>,
    resolver_conflict: bool,
}

fn full_name(label: &str, region: Option<&str>) -> String {
    match region {
        Some(region) => format!("{label}.{region}"),
        None => label.to_owned(),
    }
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

impl Names {
    /// The list for `settings` in the network `view` describes.
    pub fn build(settings: &DnsSettings, view: &NetworkView<'_>) -> Self {
        let mut scope: Vec<IpNet> = view.virtual_subnets.to_vec();
        for range in view.host_groups {
            push_unique(&mut scope, *range);
        }
        for member in view.members {
            for subnet in &member.subnets {
                push_unique(&mut scope, *subnet);
            }
        }
        let in_scope = |address: IpAddr| scope.iter().any(|net| net.contains(address));

        let region = settings.region.clone().or_else(|| {
            settings
                .names
                .iter()
                .find(|entry| view.local_addresses.contains(&entry.address))
                .map(|entry| entry.region.clone())
        });

        // The panel's entries, by name.
        let mut panel: BTreeMap<Key, Vec<IpAddr>> = BTreeMap::new();
        for entry in &settings.names {
            let key = (entry.label.clone(), Some(entry.region.clone()));
            push_unique(panel.entry(key).or_default(), entry.address);
        }
        let panel_addresses: BTreeSet<IpAddr> =
            settings.names.iter().map(|entry| entry.address).collect();

        // The members' own names, this node first. A member the panel
        // names already is known by that name only.
        let own = MemberNames {
            hostname: view.own_hostname.map(str::to_owned),
            addresses: view.local_addresses.to_vec(),
            subnets: Vec::new(),
        };
        let mut members: BTreeMap<Key, Vec<Vec<IpAddr>>> = BTreeMap::new();
        for member in std::iter::once(&own).chain(view.members) {
            let Some(hostname) = &member.hostname else {
                continue;
            };
            if member.addresses.is_empty()
                || member
                    .addresses
                    .iter()
                    .any(|address| panel_addresses.contains(address))
            {
                continue;
            }
            let label = normalize_label(hostname);
            if label.is_empty() {
                continue;
            }
            members
                .entry((label, region.clone()))
                .or_default()
                .push(member.addresses.clone());
        }

        let mut entries = Vec::new();
        let mut by_name: BTreeMap<Key, Vec<IpAddr>> = BTreeMap::new();
        let mut by_address: BTreeMap<IpAddr, Vec<String>> = BTreeMap::new();
        let mut regions = BTreeSet::new();
        let keys: BTreeSet<&Key> = panel.keys().chain(members.keys()).collect();
        for key in keys {
            let (label, key_region) = key;
            let name = full_name(label, key_region.as_deref());
            let from_panel = panel.get(key);
            let from_members = members.get(key);
            if let Some(region) = key_region {
                regions.insert(region.clone());
            }
            let mut answered = Vec::new();
            if let Some(addresses) = from_panel {
                let families = |v4: bool| addresses.iter().filter(|a| a.is_ipv4() == v4).count();
                entries.push(NameStatus {
                    name: name.clone(),
                    addresses: addresses.clone(),
                    source: NameSource::Panel,
                    duplicate: from_members.is_some() || families(true) > 1 || families(false) > 1,
                    answerable: addresses.iter().all(|a| in_scope(*a)),
                });
                for address in addresses.iter().filter(|a| in_scope(**a)) {
                    push_unique(&mut answered, *address);
                }
            }
            if let Some(groups) = from_members {
                let addresses: Vec<IpAddr> = groups.iter().flatten().copied().collect();
                entries.push(NameStatus {
                    name: name.clone(),
                    addresses: addresses.clone(),
                    source: NameSource::Member,
                    duplicate: from_panel.is_some() || groups.len() > 1,
                    answerable: addresses.iter().all(|a| in_scope(*a)),
                });
                for address in addresses.into_iter().filter(|a| in_scope(*a)) {
                    push_unique(&mut answered, address);
                }
            }
            if answered.is_empty() {
                continue;
            }
            for address in &answered {
                push_unique(by_address.entry(*address).or_default(), name.clone());
            }
            by_name.insert(key.clone(), answered);
        }

        let configured = settings.resolver_address;
        let resolver_conflict =
            configured.is_some_and(|address| view.local_addresses.contains(&address));
        Self {
            enabled: settings.enabled,
            suffix: settings.suffix.clone(),
            suffix_labels: settings
                .suffix
                .split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
            region,
            regions,
            by_name,
            by_address,
            scope,
            // Virtual subnets first, then host group ranges (spec §15.9.2
            // item 1); the 256-zone limit cuts from the end. Summary ranges
            // follow once the backbone hands them to the network.
            reverse: ReverseZones::of(view.virtual_subnets.iter().chain(view.host_groups).copied()),
            entries,
            refused: settings.refused.clone(),
            resolver_address: configured.filter(|_| !resolver_conflict),
            resolver_conflict,
        }
    }
}

/// What a query for the intranet names resolves to.
struct Resolution {
    rcode: Rcode,
    records: Vec<Record>,
    /// Some records were left out over the per-name limit.
    truncated: bool,
}

impl Resolution {
    fn empty(rcode: Rcode) -> Self {
        Self {
            rcode,
            records: Vec::new(),
            truncated: false,
        }
    }

    /// The answer message. Records left out over the per-name limit set TC
    /// over UDP only; over TCP the answer just has the first ones.
    fn write(&self, query: &Query, transport: Transport) -> Vec<u8> {
        message::answer(
            query,
            self.rcode,
            &self.records,
            TTL_SECONDS,
            self.truncated && transport == Transport::Udp,
            query.limit(transport),
        )
    }
}

/// A label as text, when it is ASCII; queries for other bytes match no name.
fn text(label: &[u8]) -> Option<String> {
    label
        .is_ascii()
        .then(|| String::from_utf8_lossy(label).into_owned())
}

/// Whether every address label of a partial reverse name is one an
/// address name can hold: a decimal octet without a leading zero, or one
/// hex digit.
fn well_formed_reverse(labels: &[Vec<u8>]) -> bool {
    let v4 = labels.len() >= 2 && labels[labels.len() - 2] == b"in-addr";
    labels[..labels.len().saturating_sub(2)]
        .iter()
        .all(|label| {
            if v4 {
                !label.is_empty()
                    && label.len() <= 3
                    && label.iter().all(u8::is_ascii_digit)
                    && (label.len() == 1 || label[0] != b'0')
                    && std::str::from_utf8(label)
                        .ok()
                        .and_then(|text| text.parse::<u8>().ok())
                        .is_some()
            } else {
                matches!(label.as_slice(), [digit] if digit.is_ascii_hexdigit())
            }
        })
}

/// The address of a complete reverse name: `d.c.b.a.in-addr.arpa` or the
/// 32 nibbles of `ip6.arpa`.
fn reverse_address(labels: &[Vec<u8>]) -> Option<IpAddr> {
    let tail = |zone: [&[u8]; 2]| {
        let n = labels.len();
        n >= 2 && labels[n - 2] == zone[0] && labels[n - 1] == zone[1]
    };
    if labels.len() == 6 && tail([&b"in-addr"[..], &b"arpa"[..]]) {
        let mut octets = [0u8; 4];
        for (i, label) in labels[..4].iter().enumerate() {
            let canonical = !label.is_empty()
                && label.len() <= 3
                && label.iter().all(u8::is_ascii_digit)
                && (label.len() == 1 || label[0] != b'0');
            if !canonical {
                return None;
            }
            octets[3 - i] = std::str::from_utf8(label).ok()?.parse().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if labels.len() == 34 && tail([&b"ip6"[..], &b"arpa"[..]]) {
        let mut value: u128 = 0;
        for (i, label) in labels[..32].iter().enumerate() {
            let [nibble] = label.as_slice() else {
                return None;
            };
            let digit = char::from(*nibble).to_digit(16)?;
            value |= u128::from(digit) << (4 * i);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(value)));
    }
    None
}

/// Address records of `qtype` from `addresses`, at most
/// [`MAX_ANSWER_ADDRESSES`] per record type.
fn address_answer(addresses: &[IpAddr], qtype: u16) -> Resolution {
    let mut records = Vec::new();
    let mut truncated = false;
    for (v4, wanted) in [
        (true, matches!(qtype, message::TYPE_A | message::TYPE_ANY)),
        (
            false,
            matches!(qtype, message::TYPE_AAAA | message::TYPE_ANY),
        ),
    ] {
        if !wanted {
            continue;
        }
        let family: Vec<IpAddr> = addresses
            .iter()
            .copied()
            .filter(|address| address.is_ipv4() == v4)
            .collect();
        truncated |= family.len() > MAX_ANSWER_ADDRESSES;
        records.extend(
            family
                .into_iter()
                .take(MAX_ANSWER_ADDRESSES)
                .map(Record::Address),
        );
    }
    Resolution {
        rcode: Rcode::NoError,
        records,
        truncated,
    }
}

impl Names {
    /// Whether names are answered at all (`dns.enabled`).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The suffix, without the final dot.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// This network's region code, when known.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The list, per name and source, sorted by name.
    pub fn entries(&self) -> &[NameStatus] {
        &self.entries
    }

    /// Entries of `dns.names` that were skipped.
    pub fn refused(&self) -> &[RefusedName] {
        &self.refused
    }

    /// The address whose port 53 the virtual interface answers; `None`
    /// when names are off, none is configured, or it is this node's own.
    pub fn resolver_address(&self) -> Option<IpAddr> {
        self.resolver_address.filter(|_| self.enabled)
    }

    /// The configured resolver address is this node's own virtual address:
    /// it is not intercepted, and the status warns.
    pub fn resolver_conflict(&self) -> bool {
        self.resolver_conflict
    }

    /// The domains this list answers for the split DNS
    /// (`tunnel.dns.matchDomains`): the suffix and the reverse zones,
    /// without the final dot; none while names are off.
    pub fn match_domains(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut domains = vec![self.suffix.clone()];
        domains.extend(self.reverse.names());
        domains
    }

    /// The reverse zones worked out for the network.
    pub fn reverse_zones(&self) -> Vec<String> {
        self.reverse.names()
    }

    /// Reverse zones left out over the limit of 256; the status warns
    /// `reverse_zones_truncated` when it is not zero.
    pub fn reverse_zones_truncated(&self) -> usize {
        self.reverse.truncated()
    }

    /// Answers `message` when it asks for an intranet name: under the
    /// suffix, a reverse name in the network's ranges, or a single label
    /// of this region. Anything else is [`Outcome::NotOurs`], so the
    /// caller's other resolvers take it.
    pub fn answer(&self, message: &[u8], transport: Transport) -> Outcome {
        if !self.enabled {
            return Outcome::NotOurs;
        }
        let Ok(query) = Query::parse(message) else {
            return Outcome::NotOurs;
        };
        match self.resolve(&query) {
            Some(resolution) => Outcome::Answer(resolution.write(&query, transport)),
            None => Outcome::NotOurs,
        }
    }

    /// The answer at the resolver address, which has no other resolver
    /// behind it: queries for other names are refused, so that the asker
    /// moves on to its next server. `None` for a message that is not a
    /// query.
    pub fn answer_at_resolver(&self, message: &[u8], transport: Transport) -> Option<Vec<u8>> {
        match Query::parse(message) {
            Err(message::ParseError::Ignore) => None,
            Err(message::ParseError::Bad(rcode)) => {
                let (id, rd, opcode) = message::header_of(message)?;
                Some(message::bare_answer(id, rd, opcode, rcode))
            }
            Ok(query) => {
                let resolution = self
                    .enabled
                    .then(|| self.resolve(&query))
                    .flatten()
                    .unwrap_or_else(|| Resolution::empty(Rcode::Refused));
                Some(resolution.write(&query, transport))
            }
        }
    }

    fn resolve(&self, query: &Query) -> Option<Resolution> {
        if query.qclass != message::CLASS_IN && query.qclass != message::CLASS_ANY {
            return None;
        }
        let labels = &query.labels;
        let n = self.suffix_labels.len();
        if labels.len() >= n && labels[labels.len() - n..] == self.suffix_labels[..] {
            return Some(self.under_suffix(&labels[..labels.len() - n], query.qtype));
        }
        if self.reverse.zone_of(labels).is_some() {
            // In a reverse zone: answered here, never passed on. A full
            // address name looks the address up; a shorter name may have
            // names below it, so it is there without data; anything else
            // does not exist.
            let full = if labels.last().is_some_and(|l| l == b"arpa")
                && labels.len() >= 2
                && labels[labels.len() - 2] == b"in-addr"
            {
                6
            } else {
                34
            };
            return Some(match reverse_address(labels) {
                Some(address) => self.reverse(address, query.qtype),
                None if labels.len() < full && well_formed_reverse(labels) => {
                    Resolution::empty(Rcode::NoError)
                }
                None => Resolution::empty(Rcode::NxDomain),
            });
        }
        if let [label] = labels.as_slice() {
            // A bare host name: this region only, else the next resolver.
            let name = text(label)?;
            let addresses = self.by_name.get(&(name, self.region.clone()))?;
            return Some(address_answer(addresses, query.qtype));
        }
        None
    }

    fn under_suffix(&self, rest: &[Vec<u8>], qtype: u16) -> Resolution {
        match rest {
            [] => Resolution::empty(Rcode::NoError),
            [label] => {
                let Some(name) = text(label) else {
                    return Resolution::empty(Rcode::NxDomain);
                };
                // A short name: this region first, then the others.
                if let Some(addresses) = self.by_name.get(&(name.clone(), self.region.clone())) {
                    return address_answer(addresses, qtype);
                }
                let mut addresses = Vec::new();
                for (_, found) in self
                    .by_name
                    .range((name.clone(), None)..)
                    .take_while(|((label, _), _)| *label == name)
                {
                    for address in found {
                        push_unique(&mut addresses, *address);
                    }
                }
                if !addresses.is_empty() {
                    address_answer(&addresses, qtype)
                } else if self.regions.contains(&name) {
                    Resolution::empty(Rcode::NoError)
                } else {
                    Resolution::empty(Rcode::NxDomain)
                }
            }
            [label, region] => {
                let (Some(name), Some(region)) = (text(label), text(region)) else {
                    return Resolution::empty(Rcode::NxDomain);
                };
                match self.by_name.get(&(name, Some(region))) {
                    Some(addresses) => address_answer(addresses, qtype),
                    None => Resolution::empty(Rcode::NxDomain),
                }
            }
            _ => Resolution::empty(Rcode::NxDomain),
        }
    }

    fn reverse(&self, address: IpAddr, qtype: u16) -> Resolution {
        let Some(names) = self.by_address.get(&address) else {
            return Resolution::empty(Rcode::NxDomain);
        };
        if !matches!(qtype, message::TYPE_PTR | message::TYPE_ANY) {
            return Resolution::empty(Rcode::NoError);
        }
        let records = names
            .iter()
            .take(MAX_ANSWER_ADDRESSES)
            .map(|name| {
                Record::Pointer(
                    name.split('.')
                        .chain(self.suffix.split('.'))
                        .map(|label| label.as_bytes().to_vec())
                        .collect(),
                )
            })
            .collect();
        Resolution {
            rcode: Rcode::NoError,
            records,
            truncated: names.len() > MAX_ANSWER_ADDRESSES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::message::tests::{parse_answer, query};
    use super::message::{TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_PTR};
    use super::*;
    use serde_json::{json, Value};

    const MX: u16 = 15;

    fn subnets() -> Vec<IpNet> {
        vec![
            IpNet::parse("10.150.0.0/16").unwrap(),
            IpNet::parse("fd00:150::/64").unwrap(),
        ]
    }

    fn settings(value: Value) -> Result<DnsSettings, &'static str> {
        let config: DnsConfig = serde_json::from_value(value).unwrap();
        config.validate(&subnets())
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn member(hostname: &str, addresses: &[&str], subnets: &[&str]) -> MemberNames {
        MemberNames {
            hostname: Some(hostname.into()),
            addresses: addresses.iter().map(|a| ip(a)).collect(),
            subnets: subnets.iter().map(|s| IpNet::parse(s).unwrap()).collect(),
        }
    }

    fn names(dns: Value, members: &[MemberNames]) -> Names {
        let settings = settings(dns).unwrap();
        let subnets = subnets();
        let local = [ip("10.150.0.5")];
        Names::build(
            &settings,
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[],
                local_addresses: &local,
                own_hostname: Some("Self-Box"),
                members,
            },
        )
    }

    fn ask(names: &Names, name: &str, qtype: u16) -> Option<message::tests::Parsed> {
        match names.answer(&query(1, name, qtype, None), Transport::Udp) {
            Outcome::Answer(reply) => Some(parse_answer(&reply)),
            Outcome::NotOurs => None,
        }
    }

    fn addresses(parsed: &message::tests::Parsed) -> Vec<IpAddr> {
        parsed
            .records
            .iter()
            .map(|(rtype, _, data)| match *rtype {
                TYPE_A => IpAddr::V4(<[u8; 4]>::try_from(data.as_slice()).unwrap().into()),
                TYPE_AAAA => IpAddr::V6(<[u8; 16]>::try_from(data.as_slice()).unwrap().into()),
                other => panic!("record type {other}"),
            })
            .collect()
    }

    fn region_dns() -> Value {
        json!({
            "enabled": true,
            "names": [
                { "name": "self-box.cn", "address": "10.150.0.5" },
                { "name": "web.cn", "address": "10.150.0.7" },
                { "name": "web.cn", "address": "fd00:150::7" },
                { "name": "web.eu", "address": "10.151.0.7" },
                { "name": "db.eu", "address": "10.151.0.9" },
                { "name": "nas.cn", "address": "192.168.10.20" },
                { "name": "far.cn", "address": "192.168.99.1" }
            ]
        })
    }

    #[test]
    fn validates_the_section() {
        let defaults = settings(json!({})).unwrap();
        assert_eq!(defaults, DnsSettings::default());
        assert_eq!(defaults.suffix, "mesh.internal");
        for (given, kept) in [
            ("mesh.internal", "mesh.internal"),
            ("a.b.internal", "a.b.internal"),
            ("Mesh.Internal", "mesh.internal"),
            ("mesh.internal.", "mesh.internal"),
            ("a-b.internal", "a-b.internal"),
        ] {
            assert_eq!(
                settings(json!({ "suffix": given })).unwrap().suffix,
                kept,
                "{given}"
            );
        }
        // Spec §15.9.2 item 1 (client audit H1): only names under
        // `internal` with at least two labels.
        for bad in [
            "com",
            "internal",
            "internal.",
            "home.arpa",
            "a.home.arpa",
            "arpa",
            "in-addr.arpa",
            "10.in-addr.arpa",
            "ip6.arpa",
            "local",
            "mesh.local",
            ".",
            "mesh.internal..",
            "example.com",
            "internal.com",
            "xinternal",
            "a..internal",
            "",
            "a_b.internal",
            "-mesh.internal",
            "mesh-.internal",
            ".mesh.internal",
            "网.internal",
        ] {
            assert!(settings(json!({ "suffix": bad })).is_err(), "{bad}");
        }
        let long = format!("{}.internal", vec!["a".repeat(60); 3].join("."));
        assert!(long.len() > MAX_SUFFIX_BYTES);
        assert!(settings(json!({ "suffix": long })).is_err());
        assert!(settings(json!({ "region": "cn" })).is_ok());
        assert!(settings(json!({ "region": "CN" })).is_err());
        assert!(settings(json!({ "region": "c.n" })).is_err());
        assert_eq!(
            settings(json!({ "enabled": true, "resolver_address": "10.150.255.254" }))
                .unwrap()
                .resolver_address,
            Some(ip("10.150.255.254"))
        );
        for bad in [
            "10.151.0.1",
            "10.150.255.255",
            "10.150.0.0",
            "resolver",
            "8.8.8.8",
        ] {
            assert!(
                settings(json!({ "enabled": true, "resolver_address": bad })).is_err(),
                "{bad}"
            );
        }
        assert!(settings(json!({ "enabled": true, "resolver_address": "fd00:150::53" })).is_ok());
        // Off: the resolver address is ignored, even a bad one.
        let off = settings(json!({ "resolver_address": "8.8.8.8" })).unwrap();
        assert_eq!(off.resolver_address, None);
        let too_many: Vec<Value> = (0..=MAX_NAMES)
            .map(|i| json!({ "name": format!("n{i}.cn"), "address": "10.150.0.1" }))
            .collect();
        assert!(settings(json!({ "names": too_many })).is_err());
        let config: Result<DnsConfig, _> = serde_json::from_value(json!({ "other": 1 }));
        assert!(config.is_err());
    }

    #[test]
    fn skips_bad_entries_and_lists_them() {
        let settings = settings(json!({
            "names": [
                { "name": "web.cn", "address": "10.150.0.7" },
                { "name": "web", "address": "10.150.0.8" },
                { "name": "a.b.cn", "address": "10.150.0.8" },
                { "name": "Web.cn", "address": "10.150.0.8" },
                { "name": "中国.cn", "address": "10.150.0.8" },
                { "name": "xn--fiqs8s.cn", "address": "10.150.0.8" },
                { "name": "pub.cn", "address": "8.8.8.8" },
                { "name": "lo.cn", "address": "127.0.0.1" },
                { "name": "ll.cn", "address": "fe80::1" },
                { "name": "mapped.cn", "address": "::ffff:10.0.0.1" },
                { "name": "junk.cn", "address": "not an address" }
            ]
        }))
        .unwrap();
        let accepted: Vec<&str> = settings.names.iter().map(|n| n.label.as_str()).collect();
        assert_eq!(accepted, ["web", "xn--fiqs8s"]);
        let refused: Vec<(&str, RefusedReason)> = settings
            .refused
            .iter()
            .map(|r| (r.name.as_str(), r.reason))
            .collect();
        assert_eq!(
            refused,
            [
                ("web", RefusedReason::InvalidName),
                ("a.b.cn", RefusedReason::InvalidName),
                ("Web.cn", RefusedReason::InvalidName),
                ("中国.cn", RefusedReason::InvalidName),
                ("pub.cn", RefusedReason::NotIntranet),
                ("lo.cn", RefusedReason::NotIntranet),
                ("ll.cn", RefusedReason::NotIntranet),
                ("mapped.cn", RefusedReason::NotIntranet),
                ("junk.cn", RefusedReason::NotIntranet),
            ]
        );
        let refused = &settings.refused[4];
        assert_eq!(refused.address, "8.8.8.8");
    }

    #[test]
    fn answers_full_short_and_bare_names() {
        // The other region is reachable here through a member's accepted
        // advertisement (a summary range does the same once the backbone
        // carries them); without it its names are not answered.
        let alone = names(
            region_dns(),
            &[member("gw", &["10.150.0.1"], &["192.168.10.0/24"])],
        );
        let unreachable = ask(&alone, "web.eu.mesh.internal", TYPE_A).unwrap();
        assert_eq!(unreachable.rcode, Rcode::NxDomain as u8);
        // A host group range is answered like a virtual subnet (spec §15.7),
        // ahead of any member's advertisement.
        let settings = settings(region_dns()).unwrap();
        let subnets = subnets();
        let local = [ip("10.150.0.5")];
        let grouped = Names::build(
            &settings,
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[IpNet::parse("10.151.0.0/24").unwrap()],
                local_addresses: &local,
                own_hostname: Some("Self-Box"),
                members: &[],
            },
        );
        let in_group = ask(&grouped, "web.eu.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&in_group), [ip("10.151.0.7")]);
        let members = [
            member("gw", &["10.150.0.1"], &["192.168.10.0/24"]),
            member("eu-border", &["10.150.0.2"], &["10.151.0.0/16"]),
        ];
        let names = names(region_dns(), &members);
        // This node's own entry gives the region.
        assert_eq!(names.region(), Some("cn"));

        let full = ask(&names, "web.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(full.rcode, 0);
        assert!(full.aa);
        assert_eq!(addresses(&full), [ip("10.150.0.7")]);
        assert!(full.records.iter().all(|(_, ttl, _)| *ttl == TTL_SECONDS));
        let v6 = ask(&names, "WEB.CN.MESH.INTERNAL", TYPE_AAAA).unwrap();
        assert_eq!(addresses(&v6), [ip("fd00:150::7")]);
        let any = ask(&names, "web.cn.mesh.internal", TYPE_ANY).unwrap();
        assert_eq!(addresses(&any), [ip("10.150.0.7"), ip("fd00:150::7")]);
        // Another region by its full name.
        let eu = ask(&names, "web.eu.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&eu), [ip("10.151.0.7")]);

        // A short name prefers this region, then looks in the others.
        let short = ask(&names, "web.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&short), [ip("10.150.0.7")]);
        let other = ask(&names, "db.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&other), [ip("10.151.0.9")]);

        // A bare host name: this region only, else not ours.
        let bare = ask(&names, "web", TYPE_A).unwrap();
        assert_eq!(addresses(&bare), [ip("10.150.0.7")]);
        assert_eq!(ask(&names, "db", TYPE_A), None);
        assert_eq!(ask(&names, "printer", TYPE_A), None);

        // A name behind a member's advertised subnet answers; one outside
        // every range does not (spec §15.9.2 item 9).
        let nas = ask(&names, "nas.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&nas), [ip("192.168.10.20")]);
        let far = ask(&names, "far.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(far.rcode, Rcode::NxDomain as u8);

        // Missing names, other types, the zone itself.
        let missing = ask(&names, "none.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(missing.rcode, Rcode::NxDomain as u8);
        let deep = ask(&names, "a.web.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(deep.rcode, Rcode::NxDomain as u8);
        let mx = ask(&names, "web.cn.mesh.internal", MX).unwrap();
        assert_eq!((mx.rcode, mx.records.len()), (0, 0));
        let apex = ask(&names, "mesh.internal", TYPE_A).unwrap();
        assert_eq!((apex.rcode, apex.records.len()), (0, 0));
        let region = ask(&names, "eu.mesh.internal", TYPE_A).unwrap();
        assert_eq!((region.rcode, region.records.len()), (0, 0));

        // Everything else belongs to the other resolvers.
        assert_eq!(ask(&names, "example.com", TYPE_A), None);
        assert_eq!(ask(&names, "web.cn.mesh.internal.example", TYPE_A), None);
    }

    #[test]
    fn duplicates_answer_every_address_panel_first() {
        let members = [
            // Claims the panel's name for another member: both answered,
            // marked, the panel's first.
            member("web", &["10.150.0.30"], &[]),
            // Two members with one host name.
            member("Build", &["10.150.0.40"], &[]),
            member("build", &["10.150.0.41"], &[]),
            // A member the panel names keeps only that name.
            member("old-name", &["10.150.0.7"], &[]),
        ];
        let names = names(region_dns(), &members);
        let web = ask(&names, "web.cn.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&web), [ip("10.150.0.7"), ip("10.150.0.30")]);
        let build = ask(&names, "build.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&build), [ip("10.150.0.40"), ip("10.150.0.41")]);
        assert_eq!(
            ask(&names, "old-name.cn.mesh.internal", TYPE_A)
                .unwrap()
                .rcode,
            Rcode::NxDomain as u8
        );

        let entry = |name: &str, source| {
            names
                .entries()
                .iter()
                .find(|e| e.name == name && e.source == source)
                .cloned()
        };
        let panel = entry("web.cn", NameSource::Panel).unwrap();
        assert!(panel.duplicate && panel.answerable);
        let claimed = entry("web.cn", NameSource::Member).unwrap();
        assert!(claimed.duplicate);
        assert_eq!(claimed.addresses, [ip("10.150.0.30")]);
        assert!(entry("build.cn", NameSource::Member).unwrap().duplicate);
        assert!(!entry("db.eu", NameSource::Panel).unwrap().duplicate);
        assert!(!entry("far.cn", NameSource::Panel).unwrap().answerable);
        // This node is named by the panel, so its host name is not used.
        assert!(entry("self-box.cn", NameSource::Member).is_none());
        assert!(entry("self-box.cn", NameSource::Panel).is_some());
        // An IPv4 and an IPv6 address of one name are not a duplicate.
        let alone = super::tests::names(region_dns(), &[]);
        let web = alone
            .entries()
            .iter()
            .find(|e| e.name == "web.cn" && e.source == NameSource::Panel)
            .unwrap();
        assert_eq!(web.addresses, [ip("10.150.0.7"), ip("fd00:150::7")]);
        assert!(!web.duplicate);
    }

    #[test]
    fn caps_answers_at_32_addresses() {
        let entries: Vec<Value> = (1..=40)
            .map(|i| json!({ "name": "many.cn", "address": format!("10.150.1.{i}") }))
            .collect();
        let names = names(json!({ "enabled": true, "names": entries }), &[]);
        let udp = ask(&names, "many.cn.mesh.internal", TYPE_A).unwrap();
        assert!(udp.tc);
        assert!(udp.records.len() <= MAX_ANSWER_ADDRESSES);
        let reply = match names.answer(
            &query(1, "many.cn.mesh.internal", TYPE_A, None),
            Transport::Tcp,
        ) {
            Outcome::Answer(reply) => parse_answer(&reply),
            Outcome::NotOurs => panic!("ours"),
        };
        assert_eq!(reply.records.len(), MAX_ANSWER_ADDRESSES);
        // Over TCP too only the first 32, without TC.
        assert!(!reply.tc);
        let first: Vec<IpAddr> = (1..=32).map(|i| ip(&format!("10.150.1.{i}"))).collect();
        assert_eq!(addresses(&reply), first);
    }

    #[test]
    fn host_group_ranges_follow_the_virtual_subnets_as_reverse_zones() {
        let settings = settings(region_dns()).unwrap();
        let subnets = subnets();
        let local = [ip("10.150.0.5")];
        let names = Names::build(
            &settings,
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[IpNet::parse("10.151.0.0/24").unwrap()],
                local_addresses: &local,
                own_hostname: Some("Self-Box"),
                members: &[],
            },
        );
        assert_eq!(
            names.reverse_zones(),
            [
                "150.10.in-addr.arpa",
                "0.0.0.0.0.0.0.0.0.5.1.0.0.0.d.f.ip6.arpa",
                "0.151.10.in-addr.arpa",
            ]
        );
        let ptr = ask(&names, "7.0.151.10.in-addr.arpa", TYPE_PTR).unwrap();
        assert_eq!((ptr.rcode, ptr.records.len()), (0, 1));
        // The rest of 10.151.0.0/16 is outside every zone.
        assert_eq!(ask(&names, "7.1.151.10.in-addr.arpa", TYPE_PTR), None);
    }

    #[test]
    fn answers_reverse_queries_in_the_network() {
        let members = [member(
            "gw",
            &["10.150.0.1", "fd00:150::1"],
            &["192.168.10.0/24"],
        )];
        let names = names(region_dns(), &members);
        let ptr = |name: &str| ask(&names, name, TYPE_PTR);
        let target = |parsed: &message::tests::Parsed| -> Vec<String> {
            parsed
                .records
                .iter()
                .map(|(rtype, _, data)| {
                    assert_eq!(*rtype, TYPE_PTR);
                    let mut labels = Vec::new();
                    let mut at = 0;
                    while data[at] != 0 {
                        let len = usize::from(data[at]);
                        labels
                            .push(String::from_utf8(data[at + 1..at + 1 + len].to_vec()).unwrap());
                        at += 1 + len;
                    }
                    labels.join(".")
                })
                .collect()
        };
        let web = ptr("7.0.150.10.in-addr.arpa").unwrap();
        assert_eq!(target(&web), ["web.cn.mesh.internal"]);
        let gw = ptr("1.0.150.10.in-addr.arpa").unwrap();
        assert_eq!(target(&gw), ["gw.cn.mesh.internal"]);
        let nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.1.0.0.0.d.f.ip6.arpa";
        assert_eq!(target(&ptr(nibbles).unwrap()), ["gw.cn.mesh.internal"]);
        // Behind an advertised subnet: no reverse zone there (spec
        // §15.9.2 item 1), so the next resolver takes it.
        assert_eq!(ptr("20.10.168.192.in-addr.arpa"), None);
        // In the network but unnamed: NXDOMAIN, never forwarded.
        let unnamed = ptr("99.0.150.10.in-addr.arpa").unwrap();
        assert_eq!(unnamed.rcode, Rcode::NxDomain as u8);
        // Named, other type: no data.
        let a = ask(&names, "7.0.150.10.in-addr.arpa", TYPE_A).unwrap();
        assert_eq!((a.rcode, a.records.len()), (0, 0));
        // The zone and names on the way to an address exist without data;
        // a label no address has does not exist.
        for name in ["150.10.in-addr.arpa", "0.150.10.in-addr.arpa"] {
            let empty = ptr(name).unwrap();
            assert_eq!((empty.rcode, empty.records.len()), (0, 0), "{name}");
        }
        for name in [
            "07.0.150.10.in-addr.arpa",
            "256.150.10.in-addr.arpa",
            "x.0.150.10.in-addr.arpa",
            "1.7.0.150.10.in-addr.arpa",
        ] {
            assert_eq!(ptr(name).unwrap().rcode, Rcode::NxDomain as u8, "{name}");
        }
        // Outside the reverse zones: not ours.
        assert_eq!(ptr("1.99.168.192.in-addr.arpa"), None);
        assert_eq!(ptr("8.8.8.8.in-addr.arpa"), None);
        assert_eq!(ptr("10.in-addr.arpa"), None);
        assert_eq!(ptr("in-addr.arpa"), None);
        assert_eq!(
            names.match_domains(),
            [
                "mesh.internal",
                "150.10.in-addr.arpa",
                "0.0.0.0.0.0.0.0.0.5.1.0.0.0.d.f.ip6.arpa"
            ]
        );
        assert_eq!(names.reverse_zones_truncated(), 0);
    }

    #[test]
    fn without_a_region_member_names_are_short_names() {
        let members = [member("gw", &["10.150.0.1"], &[])];
        let names = names(json!({ "enabled": true }), &members);
        assert_eq!(names.region(), None);
        let gw = ask(&names, "gw.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&gw), [ip("10.150.0.1")]);
        let own = ask(&names, "self-box", TYPE_A).unwrap();
        assert_eq!(addresses(&own), [ip("10.150.0.5")]);
        let statuses: Vec<&str> = names.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(statuses, ["gw", "self-box"]);
        // A configured region names them in full.
        let names = super::tests::names(json!({ "enabled": true, "region": "hk" }), &members);
        let gw = ask(&names, "gw.hk.mesh.internal", TYPE_A).unwrap();
        assert_eq!(addresses(&gw), [ip("10.150.0.1")]);
    }

    #[test]
    fn off_and_at_the_resolver() {
        let off = names(
            json!({ "enabled": false, "names": [{ "name": "web.cn", "address": "10.150.0.7" }], "resolver_address": "10.150.255.254" }),
            &[],
        );
        assert_eq!(ask(&off, "web.cn.mesh.internal", TYPE_A), None);
        assert_eq!(off.resolver_address(), None);
        assert!(off.match_domains().is_empty());
        let refused = off
            .answer_at_resolver(
                &query(1, "web.cn.mesh.internal", TYPE_A, None),
                Transport::Udp,
            )
            .unwrap();
        assert_eq!(parse_answer(&refused).rcode, Rcode::Refused as u8);

        let on = names(
            json!({ "enabled": true, "suffix": "corp.internal", "names": [{ "name": "web.cn", "address": "10.150.0.7" }], "resolver_address": "10.150.255.254" }),
            &[],
        );
        assert_eq!(on.resolver_address(), Some(ip("10.150.255.254")));
        assert!(!on.resolver_conflict());
        let at = |message: &[u8]| {
            on.answer_at_resolver(message, Transport::Udp)
                .map(|r| parse_answer(&r))
        };
        let web = at(&query(1, "web.cn.corp.internal", TYPE_A, None)).unwrap();
        assert_eq!(addresses(&web), [ip("10.150.0.7")]);
        assert_eq!(ask(&on, "web.cn.mesh.internal", TYPE_A), None);
        let other = at(&query(1, "example.com", TYPE_A, None)).unwrap();
        assert_eq!(other.rcode, Rcode::Refused as u8);
        let mut bad = query(1, "x.internal", TYPE_A, None);
        bad[5] = 2;
        assert_eq!(at(&bad).unwrap().rcode, Rcode::FormErr as u8);
        assert_eq!(at(&[1, 2, 3]), None);

        // The resolver address is this node's own: not intercepted, warned.
        let own = names(
            json!({ "enabled": true, "resolver_address": "10.150.0.5" }),
            &[],
        );
        assert_eq!(own.resolver_address(), None);
        assert!(own.resolver_conflict());
    }
}
