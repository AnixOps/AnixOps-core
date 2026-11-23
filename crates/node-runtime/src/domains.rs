//! Addresses mapped back to the domain names they were resolved from.
//!
//! A client that resolves names itself (or a layer-3 inbound such as iWAN)
//! asks the node for an IP address, so domain egress routes need the name
//! the address came from. There are two scopes:
//!
//! - The node's map ([`crate::Egress::domains`]), which every user's routing
//!   reads, learns only from an inbound's own resolver
//!   ([`DomainCache::record`]). A user cannot write to it.
//! - Each UDP session's own map ([`DomainCache::for_session`]), which learns
//!   the DNS answers relayed through that session (UDP replies from port 53)
//!   and routes only that session's datagrams. A reply is recorded only when
//!   it answers a query the same session sent: same server, transaction id
//!   and question ([`PendingQueries`]); unsolicited or spoofed replies are
//!   ignored, and one reply records at most [`MAX_ANSWERS_PER_RESPONSE`]
//!   addresses. The resolver is whatever the client chose, so its answers
//!   are trusted for that client's session and nobody else's.
//!
//! Both maps are bounded; when full, the entry recorded longest ago goes
//! first, in O(1) (amortised), so a flood of answers cannot stall the
//! lookups that share its lock, and a session flooding its own map cannot
//! evict anything from the node's map or another session's.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entries the node's map keeps at most; the one recorded longest ago goes
/// first when full.
const MAX_ENTRIES: usize = 65_536;
/// Entries one UDP session's map keeps at most. Every session has one, so
/// this keeps each one small.
pub(crate) const SESSION_MAX_ENTRIES: usize = 512;
/// Clients keep answers a little past their TTL; a short TTL still gets this.
const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = Duration::from_secs(6 * 3600);
/// Addresses one DNS reply may record; a real answer has a handful, a
/// reply built to flood the map has thousands.
pub(crate) const MAX_ANSWERS_PER_RESPONSE: usize = 16;
/// Queries one UDP session may have outstanding for recording.
const MAX_PENDING_QUERIES: usize = 64;
/// How long a relayed query waits for the reply that may be recorded.
const PENDING_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

struct Entry {
    domain: String,
    expires: Instant,
    /// Which insertion this is, to tell a live entry from a superseded one
    /// in the eviction queue.
    generation: u64,
}

struct Entries {
    /// Entries kept at most.
    capacity: usize,
    map: HashMap<IpAddr, Entry>,
    /// Insertion order, oldest first; an item whose generation no longer
    /// matches the map was overwritten or removed and is skipped.
    order: VecDeque<(IpAddr, u64)>,
    next_generation: u64,
}

impl Entries {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
        }
    }

    fn insert(&mut self, ip: IpAddr, domain: String, expires: Instant) {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.map.insert(
            ip,
            Entry {
                domain,
                expires,
                generation,
            },
        );
        self.order.push_back((ip, generation));
        while self.map.len() > self.capacity {
            let Some((oldest, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .map
                .get(&oldest)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.map.remove(&oldest);
            }
        }
        // Overwrites leave superseded items behind; drop them once they
        // outnumber the live ones, which keeps the queue bounded at an
        // amortised O(1) per insertion.
        if self.order.len() > 2 * self.capacity {
            let map = &self.map;
            self.order.retain(|(ip, generation)| {
                map.get(ip)
                    .is_some_and(|entry| entry.generation == *generation)
            });
        }
    }
}

pub struct DomainCache {
    entries: Mutex<Entries>,
}

impl Default for DomainCache {
    fn default() -> Self {
        Self::with_capacity(MAX_ENTRIES)
    }
}

impl DomainCache {
    /// The node's map: up to 65,536 entries.
    pub fn new() -> Self {
        Self::default()
    }

    /// One UDP session's map: up to [`SESSION_MAX_ENTRIES`] entries.
    pub(crate) fn for_session() -> Self {
        Self::with_capacity(SESSION_MAX_ENTRIES)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Entries::new(capacity)),
        }
    }

    /// Maps `ip` to `domain` for `ttl` (clamped to one minute .. six hours).
    pub fn record(&self, ip: IpAddr, domain: &str, ttl: Duration) {
        let Some(domain) = normalize(domain) else {
            return;
        };
        let ip = ip.to_canonical();
        let expires = Instant::now() + ttl.clamp(MIN_TTL, MAX_TTL);
        self.lock().insert(ip, domain, expires);
    }

    /// The domain `ip` was last resolved from, while its answer is fresh.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let ip = ip.to_canonical();
        let mut entries = self.lock();
        match entries.map.get(&ip) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.domain.clone()),
            Some(_) => {
                // The entry's item stays in the eviction queue; its
                // generation no longer matches, so eviction skips it. With
                // overwrites this is what leaves superseded items behind.
                entries.map.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// Records the A and AAAA answers of a DNS response under the name the
    /// client asked for (not a CNAME target), so a rule for the name the
    /// user typed matches; at most [`MAX_ANSWERS_PER_RESPONSE`] of them.
    /// Anything that is not a response is ignored. The caller must have
    /// matched the response to a query it relayed ([`PendingQueries`]);
    /// this does not check where the response came from, so a relayed
    /// response belongs in the relaying session's own map
    /// ([`DomainCache::for_session`]), never the node's.
    pub fn record_response(&self, message: &[u8]) {
        for (ip, domain, ttl) in answers(message)
            .unwrap_or_default()
            .into_iter()
            .take(MAX_ANSWERS_PER_RESPONSE)
        {
            self.record(ip, &domain, ttl);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().map.is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The DNS queries one UDP session relayed and still waits for, so only a
/// reply to one of them (same server, transaction id and question) is
/// recorded in the session's [`DomainCache`]. A reply is accepted once.
#[derive(Default)]
pub(crate) struct PendingQueries {
    /// `(transaction id, question name)` to the server the query went to
    /// (`None` when the target was a name the direct outbound resolves)
    /// and when the wait ends.
    entries: HashMap<(u16, String), (Option<SocketAddr>, Instant)>,
}

impl PendingQueries {
    /// Notes a query `message` sent to `server`; anything that is not a
    /// single-question query is ignored.
    pub(crate) fn note_query(&mut self, message: &[u8], server: Option<SocketAddr>, now: Instant) {
        let Some((id, false, name)) = question(message) else {
            return;
        };
        if self.entries.len() >= MAX_PENDING_QUERIES {
            self.entries.retain(|_, (_, deadline)| *deadline > now);
            if self.entries.len() >= MAX_PENDING_QUERIES {
                return;
            }
        }
        let server = server.map(canonical);
        self.entries
            .insert((id, name), (server, now + PENDING_QUERY_TIMEOUT));
    }

    /// Whether `message` from `source` answers a noted query; the query is
    /// forgotten when it does.
    pub(crate) fn take_reply(&mut self, message: &[u8], source: SocketAddr, now: Instant) -> bool {
        let Some((id, true, name)) = question(message) else {
            return false;
        };
        let key = (id, name);
        let Some(&(server, deadline)) = self.entries.get(&key) else {
            return false;
        };
        if deadline <= now {
            self.entries.remove(&key);
            return false;
        }
        if server.is_some_and(|server| server != canonical(source)) {
            return false;
        }
        self.entries.remove(&key);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// `(transaction id, is a response, normalised question name)` of a DNS
/// message with exactly one question.
fn question(message: &[u8]) -> Option<(u16, bool, String)> {
    let header = message.get(..12)?;
    let id = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let questions = u16::from_be_bytes([header[4], header[5]]);
    if questions != 1 {
        return None;
    }
    let (name, _) = read_name(message, 12)?;
    Some((id, flags & 0x8000 != 0, normalize(&name)?))
}

/// A host name as routes match it: lowercase, without the final dot; `None`
/// for an address or anything that is not a name.
pub(crate) fn normalize(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.');
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && name.parse::<IpAddr>().is_err();
    valid.then(|| name.to_ascii_lowercase())
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// `(address, question name, ttl)` for each A/AAAA answer of a response.
fn answers(message: &[u8]) -> Option<Vec<(IpAddr, String, Duration)>> {
    let header = message.get(..12)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    // A response (QR) without an error code.
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answer_count = u16::from_be_bytes([header[6], header[7]]);
    if questions != 1 || answer_count == 0 {
        return None;
    }
    let (question, mut position) = read_name(message, 12)?;
    position += 4; // type, class
    let mut found = Vec::new();
    for _ in 0..answer_count {
        let (_, after_name) = read_name(message, position)?;
        let fixed = message.get(after_name..after_name + 10)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data = message.get(after_name + 10..after_name + 10 + length)?;
        position = after_name + 10 + length;
        let ip = match (kind, class, data.len()) {
            (TYPE_A, CLASS_IN, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let octets: [u8; 16] = data.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => continue,
        };
        found.push((ip, question.clone(), Duration::from_secs(u64::from(ttl))));
    }
    Some(found)
}

/// Reads a possibly compressed name at `start`; returns it and the offset
/// right after it in the message (after the first pointer, if any).
fn read_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut position = start;
    let mut end = None;
    for _ in 0..128 {
        let length = *message.get(position)?;
        match length & 0xc0 {
            0x00 if length == 0 => {
                return Some((name, end.unwrap_or(position + 1)));
            }
            0x00 => {
                let label = message.get(position + 1..position + 1 + usize::from(length))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(std::str::from_utf8(label).ok()?);
                if name.len() > 253 {
                    return None;
                }
                position += 1 + usize::from(length);
            }
            0xc0 => {
                let low = *message.get(position + 1)?;
                end.get_or_insert(position + 2);
                position = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// A response for `question` with a CNAME and then one A and one AAAA.
    fn response(question: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        name(&mut message, question);
        message.extend_from_slice(&[0, 1, 0, 1]);
        // CNAME: question (pointer to offset 12) -> edge.cdn.test
        message.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30]);
        let mut target = Vec::new();
        name(&mut target, "edge.cdn.test");
        message.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let cname_at = message.len();
        message.extend_from_slice(&target);
        // A for the CNAME target, by pointer.
        message.extend_from_slice(&[0xc0, cname_at as u8, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        message.extend_from_slice(&[203, 0, 113, 7]);
        message.extend_from_slice(&[0xc0, cname_at as u8, 0, 28, 0, 1, 0, 0, 0x0e, 0x10, 0, 16]);
        message.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        message
    }

    #[test]
    fn maps_answers_to_the_question_name() {
        let cache = DomainCache::new();
        cache.record_response(&response("Chat.Example.test"));
        assert_eq!(
            cache.lookup("203.0.113.7".parse().unwrap()).as_deref(),
            Some("chat.example.test")
        );
        assert_eq!(
            cache.lookup("2001:db8::7".parse().unwrap()).as_deref(),
            Some("chat.example.test")
        );
        // An IPv4-mapped address is the same address.
        assert_eq!(
            cache
                .lookup("::ffff:203.0.113.7".parse().unwrap())
                .as_deref(),
            Some("chat.example.test")
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn ignores_queries_errors_and_garbage() {
        let cache = DomainCache::new();
        let mut query = response("a.example.test");
        query[2] = 0x01; // QR clear
        cache.record_response(&query);
        let mut failed = response("a.example.test");
        failed[3] = 0x83; // NXDOMAIN
        cache.record_response(&failed);
        let full = response("a.example.test");
        cache.record_response(&full[..full.len() - 3]);
        cache.record_response(&[0xff; 40]);
        cache.record_response(&[]);
        assert!(cache.is_empty());
    }

    #[test]
    fn refuses_pointer_loops() {
        let mut message = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(&[0xc0, 12]);
        assert!(answers(&message).is_none());
    }

    /// A query for `name` with transaction id `id`.
    fn query(id: u16, name_: &str) -> Vec<u8> {
        let mut message = id.to_be_bytes().to_vec();
        message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        name(&mut message, name_);
        message.extend_from_slice(&[0, 1, 0, 1]);
        message
    }

    #[test]
    fn records_only_replies_to_relayed_queries() {
        let now = Instant::now();
        let server: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let mut pending = PendingQueries::default();
        let reply = response("chat.example.test"); // id 0x1234
                                                   // Unsolicited: nothing was asked.
        assert!(!pending.take_reply(&reply, server, now));
        pending.note_query(&query(0x1234, "Chat.Example.test"), Some(server), now);
        // Another server, another id or another question do not match.
        let other: SocketAddr = "198.51.100.53:53".parse().unwrap();
        assert!(!pending.take_reply(&reply, other, now));
        let mut wrong_id = reply.clone();
        wrong_id[1] = 0x35;
        assert!(!pending.take_reply(&wrong_id, server, now));
        assert!(!pending.take_reply(&response("other.example.test"), server, now));
        // The real reply matches once, from the IPv4-mapped form too.
        let mapped: SocketAddr = "[::ffff:192.0.2.53]:53".parse().unwrap();
        assert!(pending.take_reply(&reply, mapped, now));
        assert!(!pending.take_reply(&reply, server, now));
        assert_eq!(pending.len(), 0);
        // A late reply is not recorded.
        pending.note_query(&query(0x1234, "chat.example.test"), Some(server), now);
        assert!(!pending.take_reply(&reply, server, now + PENDING_QUERY_TIMEOUT));
        // A query to a name target matches a reply from wherever it went.
        pending.note_query(&query(0x1234, "chat.example.test"), None, now);
        assert!(pending.take_reply(&reply, other, now));
        // A response is not a query.
        pending.note_query(&reply, Some(server), now);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn pending_queries_are_bounded() {
        let now = Instant::now();
        let server: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let mut pending = PendingQueries::default();
        for id in 0..(MAX_PENDING_QUERIES as u16 + 20) {
            pending.note_query(&query(id, "a.example.test"), Some(server), now);
        }
        assert_eq!(pending.len(), MAX_PENDING_QUERIES);
        // Expired queries make room.
        let later = now + PENDING_QUERY_TIMEOUT + Duration::from_secs(1);
        pending.note_query(&query(9999, "b.example.test"), Some(server), later);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn one_reply_records_a_bounded_number_of_addresses() {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0x01, 0x00, 0, 0, 0, 0];
        name(&mut message, "flood.example.test");
        message.extend_from_slice(&[0, 1, 0, 1]);
        for index in 0..256u16 {
            message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4]);
            message.extend_from_slice(&[10, 9, (index >> 8) as u8, index as u8]);
        }
        let cache = DomainCache::new();
        cache.record_response(&message);
        assert_eq!(cache.len(), MAX_ANSWERS_PER_RESPONSE);
    }

    #[test]
    fn evicts_the_oldest_entry_in_constant_time_when_full() {
        let cache = DomainCache::new();
        let ttl = Duration::from_secs(3600);
        let address = |index: u32| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index));
        for index in 0..MAX_ENTRIES as u32 {
            cache.record(address(index), "full.example.test", ttl);
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        // Overwriting an entry refreshes it without growing the map.
        cache.record(address(0), "again.example.test", ttl);
        assert_eq!(cache.len(), MAX_ENTRIES);
        let started = Instant::now();
        for index in 0..MAX_ENTRIES as u32 {
            cache.record(address(MAX_ENTRIES as u32 + index), "new.example.test", ttl);
        }
        // Two full-table scans per insertion would take minutes here.
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(cache.len(), MAX_ENTRIES);
        // The entries recorded first went first.
        assert!(cache.lookup(address(1)).is_none());
        assert_eq!(
            cache.lookup(address(2 * MAX_ENTRIES as u32 - 1)).as_deref(),
            Some("new.example.test")
        );
        let entries = cache.lock();
        assert!(entries.order.len() <= 2 * MAX_ENTRIES);
    }

    #[test]
    fn records_names_not_addresses() {
        let cache = DomainCache::new();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        cache.record(ip, "192.0.2.1", Duration::from_secs(60));
        cache.record(ip, "bad name", Duration::from_secs(60));
        assert!(cache.lookup(ip).is_none());
        cache.record(ip, "Api.Example.test.", Duration::from_secs(1));
        assert_eq!(cache.lookup(ip).as_deref(), Some("api.example.test"));
    }
}
