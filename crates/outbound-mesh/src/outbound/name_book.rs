//! The intranet names of the networks that run in this engine, for the
//! engine's split DNS (spec §15.9.2 item 8, first entrance; requirement
//! R28) and for the names a mesh outbound connects to.
//!
//! Each running network publishes the name list its driver built
//! ([`crate::driver::Snapshot::names`]). A query is answered from the lists
//! of every network at once ([`crate::dns::answer_from`]): managed
//! networks first (as their routes come first, spec §15.4), then in the
//! order the networks were added to the engine. That order belongs to the
//! network, so that a new instance of it (changed settings, a leave and a
//! join) keeps its place. No query is ever sent to the network (spec
//! §15.9.2 item 8).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use crate::dns::message::Transport;
use crate::dns::{self, Names, Outcome};

/// Where a network's list goes in the book: managed networks first, then
/// by the order the network was added to the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Place {
    /// `false` for a managed network, which comes first.
    not_managed: bool,
    order: u64,
}

impl Place {
    pub fn new(managed: bool, order: u64) -> Self {
        Self {
            not_managed: !managed,
            order,
        }
    }
}

/// One network's names in the book.
#[derive(Clone)]
struct Entry {
    /// The instance that published it: only that instance takes it out,
    /// so that a retiring instance cannot take out its successor's list.
    instance: u64,
    names: Arc<Names>,
}

/// The name lists of the running networks, in their places. Shared by
/// clones.
#[derive(Clone, Default)]
pub struct NameBook {
    inner: Arc<Book>,
}

#[derive(Default)]
struct Book {
    entries: Mutex<BTreeMap<Place, Entry>>,
    /// The lists of [`Self::entries`] in order, rebuilt on every change,
    /// so that a query takes no lock that a change holds for long.
    table: RwLock<Arc<[Arc<Names>]>>,
}

impl Book {
    fn rebuild(&self, entries: &BTreeMap<Place, Entry>) {
        let table: Arc<[Arc<Names>]> = entries.values().map(|entry| entry.names.clone()).collect();
        *self
            .table
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = table;
    }

    fn table(&self) -> Arc<[Arc<Names>]> {
        self.table
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl NameBook {
    /// Sets the names `instance` publishes for the network at `place`, or
    /// takes them out (`None`, and only when `instance` published them): a
    /// list that is not enabled is taken out too.
    pub fn set(&self, place: Place, instance: u64, names: Option<Arc<Names>>) {
        let mut entries = self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let changed = match names.filter(|names| names.enabled()) {
            Some(names) => {
                let same = entries.get(&place).is_some_and(|entry| {
                    entry.instance == instance && Arc::ptr_eq(&entry.names, &names)
                });
                if !same {
                    entries.insert(place, Entry { instance, names });
                }
                !same
            }
            None => {
                let own = entries
                    .get(&place)
                    .is_some_and(|entry| entry.instance == instance);
                own && entries.remove(&place).is_some()
            }
        };
        if changed {
            self.inner.rebuild(&entries);
        }
    }

    /// Answers `message` when it asks for an intranet name of a network in
    /// the book (see [`dns::answer_from`]); `None` leaves it to the other
    /// resolvers.
    pub fn answer(&self, message: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let table = self.inner.table();
        let lists: Vec<&Names> = table.iter().map(|names| names.as_ref()).collect();
        match dns::answer_from(&lists, message, transport) {
            Outcome::Answer(answer) => Some(answer),
            Outcome::NotOurs => None,
        }
    }

    /// The addresses of `host` when it is an intranet name of a network in
    /// the book, found or not (see [`dns::lookup`]); `None` for any other
    /// name.
    pub fn lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        let table = self.inner.table();
        let lists: Vec<&Names> = table.iter().map(|names| names.as_ref()).collect();
        dns::lookup(&lists, host)
    }

    /// `tunnel.dns.matchDomains`: the suffixes and reverse zones of every
    /// listed network, in order and without repeats. Empty when no
    /// network has its names enabled. Every domain listed is answered by
    /// [`Self::answer`].
    pub fn match_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = Vec::new();
        for names in self.inner.table().iter() {
            for domain in names.match_domains() {
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }
        }
        domains
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::dns::{DnsSettings, MemberNames, NetworkView};
    use crate::IpNet;

    /// A query for `name`, type A, recursion desired.
    fn query(name: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message
    }

    fn rcode(answer: &[u8]) -> u8 {
        answer[3] & 0x0f
    }

    /// The A records of an answer, in order.
    fn addresses(answer: &[u8]) -> Vec<IpAddr> {
        let count = usize::from(u16::from_be_bytes([answer[6], answer[7]]));
        // Past the header and the question.
        let mut at = 12;
        while answer[at] != 0 {
            at += 1 + usize::from(answer[at]);
        }
        at += 5;
        let mut found = Vec::new();
        for _ in 0..count {
            // Compressed owner, type, class, TTL, length, data.
            let len = usize::from(u16::from_be_bytes([answer[at + 10], answer[at + 11]]));
            let data = &answer[at + 12..at + 12 + len];
            found.push(IpAddr::from(<[u8; 4]>::try_from(data).unwrap()));
            at += 12 + len;
        }
        found
    }

    fn names(
        suffix: &str,
        enabled: bool,
        subnet: &str,
        member: Option<(&str, &str)>,
    ) -> Arc<Names> {
        let settings = DnsSettings {
            enabled,
            suffix: suffix.to_owned(),
            ..DnsSettings::default()
        };
        let subnets = [IpNet::parse(subnet).unwrap()];
        let members: Vec<MemberNames> = member
            .into_iter()
            .map(|(hostname, address)| MemberNames {
                hostname: Some(hostname.to_owned()),
                addresses: vec![address.parse::<IpAddr>().unwrap()],
                subnets: Vec::new(),
            })
            .collect();
        Arc::new(Names::build(
            &settings,
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[],
                local_addresses: &[],
                own_hostname: None,
                members: &members,
            },
        ))
    }

    #[test]
    fn a_name_is_answered_by_every_network_that_has_it() {
        let book = NameBook::default();
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp),
            None
        );
        assert!(book.match_domains().is_empty());
        // Three networks share the suffix: a legacy one added first, a
        // managed one added later, and one without the name.
        book.set(
            Place::new(false, 0),
            10,
            Some(names(
                "office.internal",
                true,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        book.set(
            Place::new(false, 1),
            11,
            Some(names("office.internal", true, "10.160.0.0/24", None)),
        );
        book.set(
            Place::new(true, 2),
            12,
            Some(names(
                "office.internal",
                true,
                "10.158.0.0/24",
                Some(("printer", "10.158.0.9")),
            )),
        );
        // Every address, the managed network's first.
        let answer = book
            .answer(&query("printer.office.internal"), Transport::Udp)
            .expect("answered");
        assert_eq!(rcode(&answer), 0);
        assert_eq!(
            addresses(&answer),
            [
                "10.158.0.9".parse::<IpAddr>().unwrap(),
                "10.157.0.9".parse().unwrap()
            ]
        );
        assert_eq!(
            book.lookup("printer.office.internal"),
            Some(vec![
                "10.158.0.9".parse().unwrap(),
                "10.157.0.9".parse().unwrap()
            ])
        );
        // A name nobody has: NXDOMAIN, nothing goes on to other resolvers.
        let missing = book
            .answer(&query("scanner.office.internal"), Transport::Udp)
            .expect("answered");
        assert_eq!(rcode(&missing), 3);
        assert_eq!(book.lookup("scanner.office.internal"), Some(Vec::new()));
        // Other names are left alone.
        assert_eq!(book.answer(&query("www.example.com"), Transport::Udp), None);
        assert_eq!(book.lookup("www.example.com"), None);
        // The domains, without repeats, every network's reverse zone.
        let domains = book.match_domains();
        assert_eq!(domains[0], "office.internal");
        assert_eq!(
            domains
                .iter()
                .filter(|domain| *domain == "office.internal")
                .count(),
            1
        );
        for zone in [
            "157.10.in-addr.arpa",
            "158.10.in-addr.arpa",
            "160.10.in-addr.arpa",
        ] {
            assert!(
                domains.iter().any(|domain| domain.ends_with(zone)),
                "{zone}"
            );
        }
    }

    #[test]
    fn a_new_instance_keeps_the_place_and_the_old_one_cannot_take_it_out() {
        let book = NameBook::default();
        let printer = |address: &str| {
            Some(names(
                "office.internal",
                true,
                "10.157.0.0/24",
                Some(("printer", address)),
            ))
        };
        book.set(Place::new(false, 0), 1, printer("10.157.0.9"));
        book.set(Place::new(false, 1), 2, printer("10.157.0.10"));
        // The first network starts a new instance: same place, and the
        // retiring instance taking its list out afterwards changes nothing.
        book.set(Place::new(false, 0), 3, printer("10.157.0.11"));
        book.set(Place::new(false, 0), 1, None);
        assert_eq!(
            book.lookup("printer.office.internal"),
            Some(vec![
                "10.157.0.11".parse().unwrap(),
                "10.157.0.10".parse().unwrap()
            ])
        );
        // Its own instance takes it out.
        book.set(Place::new(false, 0), 3, None);
        assert_eq!(
            book.lookup("printer.office.internal"),
            Some(vec!["10.157.0.10".parse().unwrap()])
        );
    }

    #[test]
    fn names_that_are_off_or_taken_out_answer_nothing() {
        let book = NameBook::default();
        let place = Place::new(false, 0);
        book.set(
            place,
            0,
            Some(names(
                "office.internal",
                false,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp),
            None
        );
        assert!(book.match_domains().is_empty());
        book.set(
            place,
            0,
            Some(names(
                "office.internal",
                true,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        assert!(book
            .answer(&query("printer.office.internal"), Transport::Udp)
            .is_some());
        book.set(place, 0, None);
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp),
            None
        );
        assert!(book.match_domains().is_empty());
    }
}
