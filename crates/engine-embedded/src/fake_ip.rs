//! Fake-IP: A queries answered at once with an address from a reserved
//! range, mapped back to the name when the app connects to it.
//!
//! With `dns.fake_ip.enabled`, the tunnel answers an `A` query for a name
//! that is not in `hosts` and not in the filter with an address from
//! [`FakeIpPool`] (TTL 1 s). With `range6` set, an `AAAA` query gets a fake
//! IPv6 address of the same slot; without it, an empty answer, so the app
//! connects over IPv4. `HTTPS` queries get an empty answer (their address
//! hints would bypass the fake addresses). The
//! [`crate::connections::Dispatcher`] turns a flow to a fake address back into
//! its name before redirects and routing, so domain rules match every
//! protocol (not only TLS and HTTP that the tunnel sniffs) and a proxy
//! resolves the name remotely; a DIRECT flow is resolved with the config's
//! `dns` section.
//!
//! The pool holds at most `max_entries` names. A name keeps its address while
//! it is in the table; a new name takes the next free address, and once the
//! table is full the CLOCK hand takes the address of a name that was not
//! asked for or connected to since the hand last passed it (an approximation
//! of least recently used without a linked list). Each entry costs about 100
//! bytes plus the name, so 100 000 names stay well under 50 MB
//! (`tests/fake_ip_memory.rs` measures it).
//!
//! Conflicts are counted, never silent:
//! - `misses`: a flow to an address in the range that maps to no name (the
//!   tunnel restarted, or the app kept an address longer than its TTL). The
//!   sniffed TLS/HTTP name is used when there is one (`recovered`), otherwise
//!   the flow is refused rather than sent to a meaningless address.
//! - `conflicts`: the sniffed name of a flow differs from the name its address
//!   maps to, i.e. the app used an address that has since been given to
//!   another name. The sniffed name wins.
//! - `recycled_young`: an address was taken from a name that had been used in
//!   the last [`YOUNG_RECYCLE`], which means the table is too small for the
//!   device's working set.
//!
//! The first 256 addresses of the range (e.g. `198.18.0.0/24` of the default
//! `198.18.0.0/15`) are never handed out: the clients put the tunnel's own
//! interface and DNS addresses there. The same holds for `range6`.
//!
//! Rebuilding the runtime (a node or group switch, a DNS change) must not
//! give an address an app still holds to another name: a flow without a
//! sniffed name (server-first TCP, UDP, QUIC) would silently go to the wrong
//! server. So the runtime takes its pool from [`FakeIpPool::retained`]: the
//! process keeps the last table, and a new runtime with the same `range`,
//! `range6` and `max_entries` goes on with it (same names, same addresses).
//! A new table (first runtime of the process, or other ranges) starts its
//! slots at a random position of the range, so an address left over from
//! an earlier table or process most likely maps to no name and is refused
//! (`misses`) instead of being read as another name.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use ring::rand::{SecureRandom, SystemRandom};

use crate::config::FakeIpConfig;
use crate::dns::{self, TYPE_A, TYPE_AAAA};

/// TTL of a fake answer, short so that apps ask again (and get the same
/// address while the name stays in the table).
pub const FAKE_TTL_SECS: u32 = 1;
/// Addresses at the start of the range kept for the tunnel's own interface.
pub const RESERVED_ADDRESSES: u32 = 256;
/// Largest table accepted.
pub const MAX_FAKE_IP_ENTRIES: usize = 1 << 20;
/// Most filter patterns (defaults included).
pub const MAX_FILTER_PATTERNS: usize = 1024;
/// An address recycled from a name used more recently than this is counted
/// in `recycled_young`.
pub const YOUNG_RECYCLE: Duration = Duration::from_secs(600);
/// DNS type of `HTTPS` (SVCB) records, whose address hints would bypass the
/// fake address.
const TYPE_HTTPS: u16 = 65;

/// Names that must get their real address: LAN names, time servers, STUN,
/// captive portal and push services, console networks.
pub const DEFAULT_FILTER: &[&str] = &[
    "+.lan",
    "+.local",
    "+.localdomain",
    "+.home.arpa",
    "+.internal",
    "localhost",
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "+.ntp.org",
    "+.pool.ntp.org",
    "time1.cloud.tencent.com",
    "stun.*.*",
    "stun.*.*.*",
    "+.stun.playstation.net",
    "+.xboxlive.com",
    "xbox.*.microsoft.com",
    "+.srv.nintendo.net",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "captive.apple.com",
    "+.push.apple.com",
    "localhost.ptlogin2.qq.com",
    "localhost.sec.qq.com",
];

/// Counters for the status; no names, no addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FakeIpStats {
    /// Names in the table now.
    pub entries: u64,
    /// Most names the table holds.
    pub capacity: u64,
    /// Addresses handed to a new name.
    pub assigned: u64,
    /// Addresses taken from an older name because the table was full.
    pub recycled: u64,
    /// Of `recycled`, those whose name was used in the last 10 minutes.
    pub recycled_young: u64,
    /// Flows to a fake address that maps to no name.
    pub misses: u64,
    /// Of `misses`, those carried on with the sniffed name.
    pub recovered: u64,
    /// Flows whose sniffed name differs from the name of their address.
    pub conflicts: u64,
}

/// A pattern of the filter: `name`, `+.name` (it and its subdomains) or a
/// pattern with `*` standing for one label (`time.*.com`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    Suffix(String),
    Labels(Vec<String>),
}

impl Pattern {
    fn parse(pattern: &str) -> Result<Self, &'static str> {
        let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        let valid = |name: &str| {
            !name.is_empty()
                && name.len() <= 253
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*'))
                && name.split('.').all(|label| !label.is_empty())
        };
        if let Some(suffix) = pattern
            .strip_prefix("+.")
            .or_else(|| pattern.strip_prefix('.'))
        {
            if !valid(suffix) || suffix.contains('*') {
                return Err("dns fake_ip filter pattern is invalid");
            }
            return Ok(Self::Suffix(suffix.to_string()));
        }
        if !valid(&pattern) {
            return Err("dns fake_ip filter pattern is invalid");
        }
        if pattern.contains('*') {
            let labels: Vec<String> = pattern.split('.').map(str::to_string).collect();
            if labels
                .iter()
                .any(|label| label.contains('*') && label != "*")
            {
                return Err("dns fake_ip filter pattern is invalid");
            }
            return Ok(Self::Labels(labels));
        }
        Ok(Self::Exact(pattern))
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Suffix(suffix) => name
                .strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.')),
            Self::Labels(labels) => {
                let mut parts = name.split('.');
                for label in labels {
                    match parts.next() {
                        Some(part) if label == "*" || part == label => {}
                        _ => return false,
                    }
                }
                parts.next().is_none()
            }
        }
    }
}

struct Slot {
    name: Option<Arc<str>>,
    /// Asked for or connected to since the hand last passed.
    referenced: bool,
    last_used: Instant,
}

struct Table {
    by_name: HashMap<Arc<str>, u32>,
    /// Grows to the capacity, then stays.
    slots: Vec<Slot>,
    hand: usize,
}

/// The table and where its slots sit in the range; shared by the pools of
/// successive runtimes with the same ranges (see [`FakeIpPool::retained`]).
struct Shared {
    /// Position in the usable range (`0..usable`) of slot 0; slot `i` is at
    /// `(offset + i) % usable`, for IPv4 and IPv6 alike.
    offset: u32,
    table: Mutex<Table>,
}

impl Shared {
    fn new(offset: u32) -> Arc<Self> {
        Arc::new(Self {
            offset,
            table: Mutex::new(Table {
                by_name: HashMap::new(),
                slots: Vec::new(),
                hand: 0,
            }),
        })
    }
}

/// What a table was built for: a new runtime reuses the retained table only
/// when all of these are the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableKey {
    network: u32,
    prefix: u8,
    v6: Option<(u128, u8)>,
    capacity: usize,
}

/// The table of the last runtime built in this process; see
/// [`FakeIpPool::retained`].
static RETAINED: Mutex<Option<(TableKey, Arc<Shared>)>> = Mutex::new(None);

/// The name ↔ address table; see the module docs. Shared by the tunnel's
/// DNS path and the dispatcher, kept across tunnel restarts of one runtime
/// and, through [`FakeIpPool::retained`], across runtimes of one process.
pub struct FakeIpPool {
    /// First address handed out.
    first: u32,
    /// Addresses after the reserved block, without the last one.
    usable: u32,
    /// Network and prefix length of the whole range.
    network: u32,
    prefix: u8,
    /// The IPv6 range, when `AAAA` queries get fake answers.
    v6: Option<Range6>,
    capacity: usize,
    filter: Vec<Pattern>,
    shared: Arc<Shared>,
    assigned: AtomicU64,
    recycled: AtomicU64,
    recycled_young: AtomicU64,
    misses: AtomicU64,
    recovered: AtomicU64,
    conflicts: AtomicU64,
}

impl std::fmt::Debug for FakeIpPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIpPool")
            .field("prefix", &self.prefix)
            .field("capacity", &self.capacity)
            .field("offset", &self.shared.offset)
            .field("filter", &self.filter.len())
            .finish()
    }
}

/// `range6`: its network, prefix length and first address handed out.
#[derive(Clone, Copy, Debug)]
struct Range6 {
    network: u128,
    prefix: u8,
    first: u128,
}

/// What the tunnel does with a DNS query when Fake-IP is on.
#[derive(Debug, PartialEq, Eq)]
pub enum FakeAnswer {
    /// Reply with this message.
    Reply(Vec<u8>),
    /// Not a fake name (filtered, not A/AAAA/HTTPS, single label): forward it.
    Forward,
}

impl FakeIpPool {
    /// The pool of a `dns.fake_ip` section, `None` when it is off, or why the
    /// section is refused (a fixed message without names). The pool has a
    /// table of its own whose first name gets the first address after the
    /// reserved block; it touches no state of the process, so it suits
    /// checking a config. A runtime takes [`Self::retained`] instead.
    pub fn from_config(config: &FakeIpConfig) -> Result<Option<Arc<Self>>, &'static str> {
        Ok(Self::build(config)?.map(Arc::new))
    }

    /// The pool of a runtime built from `config`: like [`Self::from_config`]
    /// (the filter and counters are new), but with the table the last
    /// runtime of the process used when its `range`, `range6` and
    /// `max_entries` are the same, so the names keep their addresses across
    /// the rebuild. Otherwise the pool gets a new table whose slots start at
    /// a random position of the range, and that table is the one kept.
    ///
    /// The kept table stays in memory (at most `max_entries` names) until
    /// another one replaces it or [`Self::release_retained`] drops it. Names
    /// the new filter excludes stay mapped until the CLOCK hand recycles
    /// them, so an app holding their address still reaches them.
    pub fn retained(config: &FakeIpConfig) -> Result<Option<Arc<Self>>, &'static str> {
        let Some(mut pool) = Self::build(config)? else {
            return Ok(None);
        };
        let key = pool.key();
        let mut retained = RETAINED.lock().unwrap_or_else(|e| e.into_inner());
        let kept = match &*retained {
            Some((kept, shared)) if *kept == key => Some(shared.clone()),
            _ => None,
        };
        pool.shared = match kept {
            Some(shared) => shared,
            None => {
                let shared = Shared::new(random_offset(pool.usable));
                *retained = Some((key, shared.clone()));
                shared
            }
        };
        Ok(Some(Arc::new(pool)))
    }

    /// Drops the table [`Self::retained`] keeps for the next runtime (pools
    /// that use it keep it alive); the next runtime starts a new table.
    /// Returns whether there was one.
    pub fn release_retained() -> bool {
        RETAINED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some()
    }

    fn key(&self) -> TableKey {
        TableKey {
            network: self.network,
            prefix: self.prefix,
            v6: self.v6.map(|range| (range.network, range.prefix)),
            capacity: self.capacity,
        }
    }

    fn build(config: &FakeIpConfig) -> Result<Option<Self>, &'static str> {
        if !config.enabled {
            return Ok(None);
        }
        let (network, prefix) = parse_range(&config.range)?;
        // Usable: everything after the reserved block, without the last
        // (broadcast-looking) address.
        let size = 1u64 << (32 - u32::from(prefix));
        let usable = size - u64::from(RESERVED_ADDRESSES) - 1;
        if config.max_entries == 0 || config.max_entries > MAX_FAKE_IP_ENTRIES {
            return Err("dns fake_ip max_entries is out of range");
        }
        let capacity = config.max_entries.min(usable as usize);
        // A /96 at least holds 2^32 addresses, more than any table.
        let v6 =
            config
                .range6
                .as_deref()
                .map(parse_range6)
                .transpose()?
                .map(|(network, prefix)| Range6 {
                    network,
                    prefix,
                    first: network + u128::from(RESERVED_ADDRESSES),
                });
        let mut filter = Vec::new();
        if config.default_filter {
            for pattern in DEFAULT_FILTER {
                filter.push(Pattern::parse(pattern)?);
            }
        }
        for pattern in &config.filter {
            filter.push(Pattern::parse(pattern)?);
        }
        if filter.len() > MAX_FILTER_PATTERNS {
            return Err("dns fake_ip filter has too many patterns");
        }
        Ok(Some(Self {
            first: network + RESERVED_ADDRESSES,
            // At most 2^24 - 257 for a /8.
            usable: usable as u32,
            network,
            prefix,
            v6,
            capacity,
            filter,
            shared: Shared::new(0),
            assigned: AtomicU64::new(0),
            recycled: AtomicU64::new(0),
            recycled_young: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            recovered: AtomicU64::new(0),
            conflicts: AtomicU64::new(0),
        }))
    }

    /// Most names the table holds.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether `address` is inside the configured ranges (handed out or
    /// not).
    pub fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(v4) => {
                let mask = u32::MAX << (32 - u32::from(self.prefix));
                u32::from(v4) & mask == self.network
            }
            IpAddr::V6(v6) => self.v6.is_some_and(|range| {
                let mask = u128::MAX << (128 - u32::from(range.prefix));
                u128::from(v6) & mask == range.network
            }),
        }
    }

    /// Whether `AAAA` queries get fake addresses (`range6` is set).
    pub fn has_ipv6(&self) -> bool {
        self.v6.is_some()
    }

    /// Whether `name` (lower case, no final dot) gets a fake address.
    pub fn is_fake_name(&self, name: &str) -> bool {
        name.contains('.') && !self.filter.iter().any(|pattern| pattern.matches(name))
    }

    /// The answer to `query` when it asks for a fake name, else
    /// [`FakeAnswer::Forward`].
    pub fn answer(&self, query: &[u8]) -> FakeAnswer {
        let Some(question) = dns::question(query) else {
            return FakeAnswer::Forward;
        };
        if !matches!(question.qtype, TYPE_A | TYPE_AAAA | TYPE_HTTPS)
            || !self.is_fake_name(&question.name)
        {
            return FakeAnswer::Forward;
        }
        let address = match question.qtype {
            TYPE_A => IpAddr::V4(self.assign(&question.name)),
            TYPE_AAAA => match self.assign6(&question.name) {
                Some(address) => IpAddr::V6(address),
                // No IPv6 range: the app connects to the A answer.
                None => return FakeAnswer::Reply(dns::local_answer(query, &question, &[])),
            },
            // No service hints: the app connects to the A / AAAA answers.
            _ => return FakeAnswer::Reply(dns::local_answer(query, &question, &[])),
        };
        let mut reply = dns::local_answer(query, &question, &[address]);
        // The single record ends with TTL (4), RDLENGTH (2) and the address.
        let ttl_at = reply.len() - 6 - if address.is_ipv4() { 4 } else { 16 };
        reply[ttl_at..ttl_at + 4].copy_from_slice(&FAKE_TTL_SECS.to_be_bytes());
        FakeAnswer::Reply(reply)
    }

    /// The address of `name`, handing it one if it has none.
    pub fn assign(&self, name: &str) -> Ipv4Addr {
        self.address_of(self.slot(name))
    }

    /// The IPv6 address of `name` (the same slot as its IPv4 one), handing
    /// it one if it has none; `None` without `range6`.
    pub fn assign6(&self, name: &str) -> Option<Ipv6Addr> {
        let range = self.v6?;
        let position = self.position(self.slot(name));
        Some(Ipv6Addr::from(range.first + u128::from(position)))
    }

    /// The slot of `name`, taking one if it has none.
    fn slot(&self, name: &str) -> u32 {
        let now = Instant::now();
        let mut table = self.shared.table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&index) = table.by_name.get(name) {
            let slot = &mut table.slots[index as usize];
            slot.referenced = true;
            slot.last_used = now;
            return index;
        }
        let name: Arc<str> = Arc::from(name);
        self.assigned.fetch_add(1, Ordering::Relaxed);
        let index = if table.slots.len() < self.capacity {
            table.slots.push(Slot {
                name: Some(name.clone()),
                referenced: false,
                last_used: now,
            });
            table.slots.len() - 1
        } else {
            // CLOCK: skip (and clear) recently used slots; at most two turns.
            let index = loop {
                let hand = table.hand;
                table.hand = (hand + 1) % self.capacity;
                let slot = &mut table.slots[hand];
                if slot.referenced {
                    slot.referenced = false;
                    continue;
                }
                break hand;
            };
            let slot = &mut table.slots[index];
            let old = slot.name.replace(name.clone());
            let young = now.saturating_duration_since(slot.last_used) < YOUNG_RECYCLE;
            slot.last_used = now;
            if let Some(old) = old {
                table.by_name.remove(&old);
                self.recycled.fetch_add(1, Ordering::Relaxed);
                if young {
                    self.recycled_young.fetch_add(1, Ordering::Relaxed);
                }
            }
            index
        };
        let index = index as u32;
        table.by_name.insert(name, index);
        index
    }

    /// The name `address` maps to, marking it used; `None` outside the
    /// range or for an address no name holds.
    pub fn lookup(&self, address: IpAddr) -> Option<Arc<str>> {
        if !self.contains(address) {
            return None;
        }
        let position = match address {
            IpAddr::V4(v4) => u32::from(v4).checked_sub(self.first)?,
            IpAddr::V6(v6) => u32::try_from(u128::from(v6).checked_sub(self.v6?.first)?).ok()?,
        };
        let index = self.index_at(position)? as usize;
        let mut table = self.shared.table.lock().unwrap_or_else(|e| e.into_inner());
        let slot = table.slots.get_mut(index)?;
        let name = slot.name.clone()?;
        slot.referenced = true;
        slot.last_used = Instant::now();
        Some(name)
    }

    /// The name to connect to for a flow to `address` (in the range), with
    /// `sniffed` the name read from its first bytes. Counts misses and
    /// conflicts; `None` refuses the flow.
    pub fn resolve_flow(&self, address: IpAddr, sniffed: Option<&str>) -> Option<String> {
        let sniffed = sniffed
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| name.parse::<IpAddr>().is_err() && !name.is_empty());
        match (self.lookup(address), sniffed) {
            (Some(mapped), Some(sniffed)) => {
                if *mapped != *sniffed {
                    self.conflicts.fetch_add(1, Ordering::Relaxed);
                }
                Some(sniffed)
            }
            (Some(mapped), None) => Some(mapped.to_string()),
            (None, Some(sniffed)) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.recovered.fetch_add(1, Ordering::Relaxed);
                Some(sniffed)
            }
            (None, None) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn stats(&self) -> FakeIpStats {
        let entries = self
            .shared
            .table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_name
            .len() as u64;
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        FakeIpStats {
            entries,
            capacity: self.capacity as u64,
            assigned: get(&self.assigned),
            recycled: get(&self.recycled),
            recycled_young: get(&self.recycled_young),
            misses: get(&self.misses),
            recovered: get(&self.recovered),
            conflicts: get(&self.conflicts),
        }
    }

    fn address_of(&self, index: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.first + self.position(index))
    }

    /// Where slot `index` (below the capacity) sits in the usable range.
    fn position(&self, index: u32) -> u32 {
        ((u64::from(self.shared.offset) + u64::from(index)) % u64::from(self.usable)) as u32
    }

    /// The slot at `position` of the usable range, `None` past its end.
    fn index_at(&self, position: u32) -> Option<u32> {
        if position >= self.usable {
            return None;
        }
        let usable = u64::from(self.usable);
        Some(((u64::from(position) + usable - u64::from(self.shared.offset)) % usable) as u32)
    }
}

/// A random position in `0..usable`, `0` if the system has no randomness.
fn random_offset(usable: u32) -> u32 {
    let mut bytes = [0u8; 4];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u32::from_be_bytes(bytes) % usable
}

/// `x::/len` with 8 <= len <= 96, the network address aligned.
fn parse_range6(range: &str) -> Result<(u128, u8), &'static str> {
    const INVALID: &str = "dns fake_ip range6 must be an IPv6 network from /8 to /96";
    let (address, prefix) = range.trim().split_once('/').ok_or(INVALID)?;
    let address: Ipv6Addr = address.parse().map_err(|_| INVALID)?;
    let prefix: u8 = prefix.parse().map_err(|_| INVALID)?;
    if !(8..=96).contains(&prefix) {
        return Err(INVALID);
    }
    let network = u128::from(address);
    let mask = u128::MAX << (128 - u32::from(prefix));
    if network & mask != network {
        return Err(INVALID);
    }
    Ok((network, prefix))
}

/// `a.b.c.d/len` with 8 <= len <= 22, the network address aligned.
fn parse_range(range: &str) -> Result<(u32, u8), &'static str> {
    const INVALID: &str = "dns fake_ip range must be an IPv4 network from /8 to /22";
    let (address, prefix) = range.trim().split_once('/').ok_or(INVALID)?;
    let address: Ipv4Addr = address.parse().map_err(|_| INVALID)?;
    let prefix: u8 = prefix.parse().map_err(|_| INVALID)?;
    if !(8..=22).contains(&prefix) {
        return Err(INVALID);
    }
    let network = u32::from(address);
    let mask = u32::MAX << (32 - u32::from(prefix));
    if network & mask != network {
        return Err(INVALID);
    }
    Ok((network, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_entries: usize) -> FakeIpConfig {
        FakeIpConfig {
            enabled: true,
            max_entries,
            ..FakeIpConfig::default()
        }
    }

    fn pool(max_entries: usize) -> Arc<FakeIpPool> {
        FakeIpPool::from_config(&config(max_entries))
            .unwrap()
            .unwrap()
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        dns::query(0x4242, name, qtype).unwrap()
    }

    #[test]
    fn off_by_default() {
        assert!(FakeIpPool::from_config(&FakeIpConfig::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn names_keep_their_address_and_map_back() {
        let pool = pool(16);
        let a = pool.assign("a.example");
        let b = pool.assign("b.example");
        assert_eq!(a, Ipv4Addr::new(198, 18, 1, 0));
        assert_eq!(b, Ipv4Addr::new(198, 18, 1, 1));
        assert_eq!(pool.assign("a.example"), a);
        assert_eq!(pool.lookup(IpAddr::V4(b)).as_deref(), Some("b.example"));
        assert!(pool.contains(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
        assert!(pool.contains(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))));
        assert!(!pool.contains(IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1))));
        assert_eq!(pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))), None);
        assert_eq!(pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 9))), None);
        assert_eq!(pool.stats().entries, 2);
        assert_eq!(pool.stats().assigned, 2);
    }

    #[test]
    fn a_full_table_recycles_the_least_recently_used() {
        let pool = pool(3);
        let a = pool.assign("a.example");
        let b = pool.assign("b.example");
        let c = pool.assign("c.example");
        // Use a and c again: b is the one to go.
        pool.assign("a.example");
        pool.lookup(IpAddr::V4(c));
        let d = pool.assign("d.example");
        assert_eq!(d, b);
        assert_eq!(pool.lookup(IpAddr::V4(a)).as_deref(), Some("a.example"));
        assert_eq!(pool.lookup(IpAddr::V4(d)).as_deref(), Some("d.example"));
        let stats = pool.stats();
        assert_eq!(stats.entries, 3);
        assert_eq!(stats.recycled, 1);
        assert_eq!(stats.recycled_young, 1);
    }

    #[test]
    fn conflicts_and_misses_are_counted() {
        let pool = pool(1);
        let a = IpAddr::V4(pool.assign("a.example"));
        // The address now belongs to b; an app still using it for a.example
        // is caught by the name it sends.
        pool.assign("b.example");
        assert_eq!(
            pool.resolve_flow(a, Some("a.example")).as_deref(),
            Some("a.example")
        );
        assert_eq!(pool.stats().conflicts, 1);
        assert_eq!(pool.resolve_flow(a, None).as_deref(), Some("b.example"));
        let unused = IpAddr::V4(Ipv4Addr::new(198, 18, 9, 9));
        assert_eq!(pool.resolve_flow(unused, None), None);
        assert_eq!(
            pool.resolve_flow(unused, Some("C.Example.")).as_deref(),
            Some("c.example")
        );
        let stats = pool.stats();
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.recovered, 1);
        assert_eq!(stats.conflicts, 1);
    }

    #[test]
    fn answers_a_with_a_one_second_fake_and_empties_aaaa() {
        let pool = pool(16);
        let FakeAnswer::Reply(reply) = pool.answer(&query("www.example.com", TYPE_A)) else {
            panic!("expected a fake answer");
        };
        assert_eq!(&reply[..2], &[0x42, 0x42]);
        assert_eq!(&reply[6..8], &[0, 1], "one answer");
        assert!(reply.ends_with(&[0, 0, 0, 1, 0, 4, 198, 18, 1, 0]));
        let FakeAnswer::Reply(reply) = pool.answer(&query("www.example.com", TYPE_AAAA)) else {
            panic!("expected an empty answer");
        };
        assert_eq!(&reply[6..8], &[0, 0]);
        assert_eq!(
            pool.answer(&query("www.example.com", 15)),
            FakeAnswer::Forward,
            "MX goes upstream"
        );
        assert_eq!(pool.answer(&query("printer", TYPE_A)), FakeAnswer::Forward);
    }

    #[test]
    fn range6_answers_aaaa_from_the_same_slot() {
        let pool = FakeIpPool::from_config(&FakeIpConfig {
            range6: Some("fc00::/18".to_string()),
            ..config(16)
        })
        .unwrap()
        .unwrap();
        assert!(pool.has_ipv6());
        let FakeAnswer::Reply(reply) = pool.answer(&query("www.example.com", TYPE_AAAA)) else {
            panic!("expected a fake AAAA answer");
        };
        assert_eq!(&reply[6..8], &[0, 1], "one answer");
        let fake: Ipv6Addr = "fc00::100".parse().unwrap();
        let mut tail = vec![0, 0, 0, 1, 0, 16];
        tail.extend_from_slice(&fake.octets());
        assert!(
            reply.ends_with(&tail),
            "TTL 1, first address after the reserved block"
        );
        // The A answer for the name uses the same slot.
        assert_eq!(pool.assign("www.example.com"), Ipv4Addr::new(198, 18, 1, 0));
        assert_eq!(pool.assign6("www.example.com"), Some(fake));
        assert_eq!(pool.stats().entries, 1);
        assert_eq!(
            pool.lookup(IpAddr::V6(fake)).as_deref(),
            Some("www.example.com")
        );
        assert!(pool.contains(IpAddr::V6("fc00:3fff::1".parse().unwrap())));
        assert!(!pool.contains(IpAddr::V6("fc00:4000::1".parse().unwrap())));
        assert_eq!(pool.lookup(IpAddr::V6("fc00::1".parse().unwrap())), None);
        assert_eq!(pool.lookup(IpAddr::V6("fc00::200".parse().unwrap())), None);
        // Service hints stay empty.
        let FakeAnswer::Reply(reply) = pool.answer(&query("www.example.com", TYPE_HTTPS)) else {
            panic!("expected an empty answer");
        };
        assert_eq!(&reply[6..8], &[0, 0]);

        // Without range6, no IPv6 address is fake.
        let v4_only = pool_with_names(&[]);
        assert!(!v4_only.has_ipv6());
        assert!(!v4_only.contains(IpAddr::V6(fake)));
        assert_eq!(v4_only.assign6("www.example.com"), None);
    }

    #[test]
    fn an_offset_table_wraps_around_the_usable_range() {
        let mut pool = FakeIpPool::build(&FakeIpConfig {
            range: "10.90.0.0/22".to_string(),
            range6: Some("fc00::/96".to_string()),
            ..config(16)
        })
        .unwrap()
        .unwrap();
        // 1024 addresses: 256 reserved, the last one never handed out.
        assert_eq!(pool.usable, 767);
        pool.shared = Shared::new(766);
        let a = pool.assign("a.example");
        let b = pool.assign("b.example");
        assert_eq!(
            a,
            Ipv4Addr::new(10, 90, 3, 254),
            "slot 0 at the last position"
        );
        assert_eq!(b, Ipv4Addr::new(10, 90, 1, 0), "slot 1 wraps to the first");
        assert_eq!(pool.lookup(IpAddr::V4(a)).as_deref(), Some("a.example"));
        assert_eq!(pool.lookup(IpAddr::V4(b)).as_deref(), Some("b.example"));
        assert_eq!(
            pool.assign6("b.example"),
            Some("fc00::100".parse().unwrap()),
            "IPv6 uses the same position"
        );
        let a6: Ipv6Addr = "fc00::3fe".parse().unwrap();
        assert_eq!(pool.assign6("a.example"), Some(a6));
        assert_eq!(pool.lookup(IpAddr::V6(a6)).as_deref(), Some("a.example"));
        // Positions no slot holds, the last address and the reserved block
        // map to no name.
        for unused in [
            Ipv4Addr::new(10, 90, 1, 1),
            Ipv4Addr::new(10, 90, 3, 253),
            Ipv4Addr::new(10, 90, 3, 255),
            Ipv4Addr::new(10, 90, 0, 7),
        ] {
            assert_eq!(pool.lookup(IpAddr::V4(unused)), None, "{unused}");
        }
        assert_eq!(pool.lookup(IpAddr::V6("fc00::3ff".parse().unwrap())), None);
        assert_eq!(pool.stats().entries, 2);
    }

    fn pool_with_names(names: &[&str]) -> Arc<FakeIpPool> {
        let pool = pool(16);
        for name in names {
            pool.assign(name);
        }
        pool
    }

    #[test]
    fn the_filter_keeps_real_answers() {
        let pool = FakeIpPool::from_config(&FakeIpConfig {
            filter: vec!["+.corp.example".to_string(), "api.*.example".to_string()],
            ..config(16)
        })
        .unwrap()
        .unwrap();
        for name in [
            "nas.lan",
            "time.apple.com",
            "time.windows.com",
            "0.pool.ntp.org",
            "stun.l.google.com",
            "captive.apple.com",
            "1-courier.push.apple.com",
            "corp.example",
            "git.corp.example",
            "api.eu.example",
        ] {
            assert!(!pool.is_fake_name(name), "{name} must not be fake");
        }
        for name in [
            "www.apple.com",
            "api.example",
            "api.a.b.example",
            "example.com",
        ] {
            assert!(pool.is_fake_name(name), "{name} must be fake");
        }
        let unfiltered = FakeIpPool::from_config(&FakeIpConfig {
            default_filter: false,
            ..config(16)
        })
        .unwrap()
        .unwrap();
        assert!(unfiltered.is_fake_name("time.apple.com"));
    }

    #[test]
    fn bad_sections_are_refused() {
        for range in [
            "198.18.0.1/15",
            "198.18.0.0/24",
            "198.18.0.0",
            "::/64",
            "10.0.0.0/7",
        ] {
            let section = FakeIpConfig {
                range: range.to_string(),
                ..config(16)
            };
            assert!(FakeIpPool::from_config(&section).is_err(), "{range}");
        }
        for range6 in [
            "fc00::1/18",
            "fc00::/7",
            "fc00::/97",
            "198.18.0.0/15",
            "fc00::",
        ] {
            let section = FakeIpConfig {
                range6: Some(range6.to_string()),
                ..config(16)
            };
            assert!(FakeIpPool::from_config(&section).is_err(), "{range6}");
        }
        assert!(FakeIpPool::from_config(&config(0)).is_err());
        assert!(FakeIpPool::from_config(&config(MAX_FAKE_IP_ENTRIES + 1)).is_err());
        for pattern in ["", "a..b", "+.*.example", "a*.example"] {
            let section = FakeIpConfig {
                filter: vec![pattern.to_string()],
                ..config(16)
            };
            assert!(FakeIpPool::from_config(&section).is_err(), "{pattern:?}");
        }
    }

    #[test]
    fn a_small_range_caps_the_table() {
        let pool = FakeIpPool::from_config(&FakeIpConfig {
            range: "10.10.0.0/22".to_string(),
            ..config(100_000)
        })
        .unwrap()
        .unwrap();
        assert_eq!(pool.capacity(), 1024 - 256 - 1);
    }
}
