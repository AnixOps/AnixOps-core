//! The intranet names of the networks that run in this engine, for the
//! engine's split DNS (spec §15.9.2 item 8, first entrance; requirement
//! R28).
//!
//! Each running network publishes the name list its driver built
//! ([`crate::driver::Snapshot::names`]); a query is answered from the
//! lists of the networks the caller names, in the order they joined. No
//! query is ever sent to the network (spec §15.9.2 item 8).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::dns::message::Transport;
use crate::dns::{Names, Outcome};

/// One network's names in the book.
#[derive(Clone)]
struct Entry {
    network: Arc<str>,
    names: Arc<Names>,
}

/// The name lists of the running networks, by the order they joined.
/// Shared by clones.
#[derive(Clone, Default)]
pub struct NameBook {
    inner: Arc<Book>,
}

#[derive(Default)]
struct Book {
    entries: Mutex<BTreeMap<u64, Entry>>,
    /// [`Self::entries`] in order, rebuilt on every change, so that a
    /// query takes no lock that a change holds for long.
    table: RwLock<Arc<[Entry]>>,
}

impl Book {
    fn rebuild(&self, entries: &BTreeMap<u64, Entry>) {
        let table: Arc<[Entry]> = entries.values().cloned().collect();
        *self
            .table
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = table;
    }

    fn table(&self) -> Arc<[Entry]> {
        self.table
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// How much `answer` says, by its DNS header: 2 for records, 1 for a
/// name that exists without records of the type asked (NOERROR), 0 for
/// anything else (NXDOMAIN, a malformed query).
fn rank(answer: &[u8]) -> u8 {
    if answer.len() < 12 || answer[3] & 0x0f != 0 {
        return 0;
    }
    if answer[6] != 0 || answer[7] != 0 {
        2
    } else {
        1
    }
}

impl NameBook {
    /// Sets the names of the instance numbered `order` (its owner number)
    /// of `network`, or takes them out (`None`): a list that is not
    /// enabled is taken out too.
    pub fn set(&self, order: u64, network: &str, names: Option<Arc<Names>>) {
        let mut entries = self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let changed = match names.filter(|names| names.enabled()) {
            Some(names) => {
                let same = entries
                    .get(&order)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.names, &names));
                if !same {
                    entries.insert(
                        order,
                        Entry {
                            network: Arc::from(network),
                            names,
                        },
                    );
                }
                !same
            }
            None => entries.remove(&order).is_some(),
        };
        if changed {
            self.inner.rebuild(&entries);
        }
    }

    /// Answers `message` when it asks for an intranet name of one of the
    /// networks `wanted` accepts; `None` leaves it to the other resolvers.
    /// Several networks may share a suffix: the answer that says the most
    /// wins (records, then a name without records of that type, then
    /// NXDOMAIN), the first in the order the networks joined among equals.
    pub fn answer(
        &self,
        message: &[u8],
        transport: Transport,
        wanted: impl Fn(&str) -> bool,
    ) -> Option<Vec<u8>> {
        let mut best: Option<(u8, Vec<u8>)> = None;
        for entry in self.inner.table().iter() {
            if !wanted(&entry.network) {
                continue;
            }
            if let Outcome::Answer(answer) = entry.names.answer(message, transport) {
                let rank = rank(&answer);
                if rank == 2 {
                    return Some(answer);
                }
                let better = match &best {
                    Some((best, _)) => rank > *best,
                    None => true,
                };
                if better {
                    best = Some((rank, answer));
                }
            }
        }
        best.map(|(_, answer)| answer)
    }

    /// `tunnel.dns.matchDomains`: the suffixes and reverse zones of every
    /// listed network, in order and without repeats. Empty when no
    /// network has its names enabled.
    pub fn match_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = Vec::new();
        for entry in self.inner.table().iter() {
            for domain in entry.names.match_domains() {
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

    fn everyone(_: &str) -> bool {
        true
    }

    #[test]
    fn a_name_is_answered_by_the_network_that_has_it() {
        let book = NameBook::default();
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp, everyone),
            None
        );
        assert!(book.match_domains().is_empty());
        // Two networks share the suffix; only the second has the name.
        book.set(
            0,
            "lab",
            Some(names("office.internal", true, "10.160.0.0/24", None)),
        );
        book.set(
            1,
            "office",
            Some(names(
                "office.internal",
                true,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        let answer = book
            .answer(&query("printer.office.internal"), Transport::Udp, everyone)
            .expect("answered");
        assert_eq!(rank(&answer), 2);
        assert_eq!(rcode(&answer), 0);
        // A name nobody has: the first network's answer, NXDOMAIN, and
        // nothing goes on to other resolvers.
        let missing = book
            .answer(&query("scanner.office.internal"), Transport::Udp, everyone)
            .expect("answered");
        assert_eq!(rank(&missing), 0);
        assert_eq!(rcode(&missing), 3);
        // Other names are left alone.
        assert_eq!(
            book.answer(&query("www.example.com"), Transport::Udp, everyone),
            None
        );
        // Only the networks the caller wants answer.
        let missing = book
            .answer(
                &query("printer.office.internal"),
                Transport::Udp,
                |network| network == "lab",
            )
            .expect("answered by lab");
        assert_eq!(rank(&missing), 0);
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp, |_| false),
            None
        );
        // The domains, without repeats.
        let domains = book.match_domains();
        assert_eq!(domains[0], "office.internal");
        assert_eq!(
            domains
                .iter()
                .filter(|domain| *domain == "office.internal")
                .count(),
            1
        );
        assert!(domains.iter().any(
            |domain| domain == "160.10.in-addr.arpa" || domain.ends_with("160.10.in-addr.arpa")
        ));
    }

    #[test]
    fn names_that_are_off_or_taken_out_answer_nothing() {
        let book = NameBook::default();
        book.set(
            0,
            "office",
            Some(names(
                "office.internal",
                false,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp, everyone),
            None
        );
        assert!(book.match_domains().is_empty());
        book.set(
            0,
            "office",
            Some(names(
                "office.internal",
                true,
                "10.157.0.0/24",
                Some(("printer", "10.157.0.9")),
            )),
        );
        assert!(book
            .answer(&query("printer.office.internal"), Transport::Udp, everyone)
            .is_some());
        book.set(0, "office", None);
        assert_eq!(
            book.answer(&query("printer.office.internal"), Transport::Udp, everyone),
            None
        );
        assert!(book.match_domains().is_empty());
    }
}
