//! The subnets the networks of one process route, and their virtual
//! address ranges, shared so that no two networks route overlapping
//! subnets (spec §15.4, 同一进程中的多个网络). The standalone node
//! (`anixops-mesh`) installs what a network holds here as system routes;
//! the embedded engine routes flows by it ([`HostRoutes::lookup`]).
//!
//! Each network treats what the others hold as one of this machine's
//! networks, which refuses it as an overlap. A subnet goes to the first
//! network to claim it, except that a `managed` network takes it from a
//! `legacy` one; a virtual address range is never taken.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use tokio::sync::watch;

use crate::IpNet;

/// What one network of this process holds.
#[derive(Debug, Default)]
struct Holder {
    /// A `managed` network: its claims take precedence over `legacy`
    /// networks' (spec §15.4).
    managed: bool,
    /// Its virtual address ranges, on its interface.
    interface: Vec<IpNet>,
    /// The subnets it holds, sorted.
    routes: Vec<IpNet>,
    /// When it joined, counted: of two networks on one virtual range, the
    /// earlier one is looked up.
    joined: u64,
}

/// Sorted and without repeats, so that claims compare as sets.
fn sorted(mut nets: Vec<IpNet>) -> Vec<IpNet> {
    nets.sort_by_key(|net| (net.network(), net.prefix()));
    nets.dedup();
    nets
}

#[derive(Default)]
struct State {
    holders: BTreeMap<String, Holder>,
    joins: u64,
}

/// One entry of the lookup table: a network and its owner.
type Entry = (IpNet, Arc<str>);

/// See the module documentation. Clones share one state.
#[derive(Clone)]
pub struct HostRoutes {
    inner: Arc<HostRoutesInner>,
}

struct HostRoutesInner {
    state: Mutex<State>,
    /// Counts changes, so that the other networks look again.
    changed: watch::Sender<u64>,
    /// Every virtual range and held subnet with its owner, most specific
    /// first: built at each change, so that a lookup takes no other lock
    /// and copies nothing.
    table: RwLock<Arc<[Entry]>>,
}

impl Default for HostRoutes {
    fn default() -> Self {
        Self {
            inner: Arc::new(HostRoutesInner {
                state: Mutex::new(State::default()),
                changed: watch::channel(0).0,
                table: RwLock::new(Arc::from(Vec::new())),
            }),
        }
    }
}

/// An IPv4-mapped IPv6 address as the IPv4 address it stands for.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

impl HostRoutes {
    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Rebuilds the lookup table from `state` and tells the networks.
    fn changed(&self, state: &State) {
        let mut entries: Vec<(u8, bool, u64, bool, IpNet, &str)> = Vec::new();
        for (owner, holder) in &state.holders {
            for (route, net) in holder
                .interface
                .iter()
                .map(|net| (false, net))
                .chain(holder.routes.iter().map(|net| (true, net)))
            {
                // Most specific first; on one prefix a managed network,
                // then the one that joined first.
                entries.push((
                    u8::MAX - net.prefix(),
                    !holder.managed,
                    holder.joined,
                    route,
                    *net,
                    owner,
                ));
            }
        }
        entries.sort_by(|a, b| (a.0, a.1, a.2, a.3).cmp(&(b.0, b.1, b.2, b.3)));
        let mut owners: BTreeMap<&str, Arc<str>> = BTreeMap::new();
        let table: Vec<Entry> = entries
            .into_iter()
            .map(|(.., net, owner)| {
                let owner = owners.entry(owner).or_insert_with(|| Arc::from(owner));
                (net, owner.clone())
            })
            .collect();
        *self
            .inner
            .table
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::from(table);
        self.inner.changed.send_modify(|count| *count += 1);
    }

    /// Records `owner`, of the given kind and with its virtual address
    /// ranges, before it claims anything: the other networks see the
    /// ranges at once, and give up any subnet they held in them.
    pub fn join(&self, owner: &str, managed: bool, interface: &[IpNet]) {
        let mut state = self.state();
        state.joins += 1;
        let joined = state.joins;
        let interface = sorted(interface.iter().map(IpNet::trunc).collect());
        for (other, holder) in state.holders.iter_mut() {
            if other != owner {
                holder
                    .routes
                    .retain(|route| !interface.iter().any(|range| range.overlaps(route)));
            }
        }
        let holder = state.holders.entry(owner.to_owned()).or_default();
        holder.managed = managed;
        holder.interface = interface;
        holder.joined = joined;
        self.changed(&state);
    }

    /// Claims for `owner` the subnets of `wanted` that overlap neither
    /// another network's virtual range nor a subnet another network holds
    /// with the same or a higher precedence; a `managed` owner takes
    /// overlapping subnets from `legacy` networks. Gives up the rest of
    /// what it held and returns what it now holds, sorted. Others are told
    /// only when something changed.
    pub fn claim(&self, owner: &str, wanted: &[IpNet]) -> Vec<IpNet> {
        let mut state = self.state();
        let managed = state
            .holders
            .get(owner)
            .is_some_and(|holder| holder.managed);
        let held = sorted(
            wanted
                .iter()
                .filter(|net| {
                    !state
                        .holders
                        .iter()
                        .filter(|(other, _)| other.as_str() != owner)
                        .any(|(_, holder)| {
                            holder.interface.iter().any(|range| range.overlaps(net))
                                || ((holder.managed || !managed)
                                    && holder.routes.iter().any(|route| route.overlaps(net)))
                        })
                })
                .copied()
                .collect(),
        );
        let mut changed = false;
        if managed {
            for (other, holder) in state.holders.iter_mut() {
                if other.as_str() == owner || holder.managed {
                    continue;
                }
                let before = holder.routes.len();
                holder
                    .routes
                    .retain(|route| !held.iter().any(|net| net.overlaps(route)));
                changed |= holder.routes.len() != before;
            }
        }
        let holder = state.holders.entry(owner.to_owned()).or_default();
        if holder.routes != held {
            holder.routes = held.clone();
            changed = true;
        }
        if changed {
            self.changed(&state);
        }
        held
    }

    /// Keeps of `owner`'s claim only what it installed.
    pub fn narrow(&self, owner: &str, installed: &[IpNet]) {
        let mut state = self.state();
        let Some(holder) = state.holders.get_mut(owner) else {
            return;
        };
        let before = holder.routes.len();
        holder.routes.retain(|route| installed.contains(route));
        if holder.routes.len() != before {
            self.changed(&state);
        }
    }

    /// What `owner` treats as this machine's networks of the others:
    /// every virtual range, and the subnets held with the same or a higher
    /// precedence (a `managed` owner may take a `legacy` network's), sorted.
    pub fn others(&self, owner: &str) -> Vec<IpNet> {
        let state = self.state();
        let managed = state
            .holders
            .get(owner)
            .is_some_and(|holder| holder.managed);
        sorted(
            state
                .holders
                .iter()
                .filter(|(other, _)| other.as_str() != owner)
                .flat_map(|(_, holder)| {
                    let routes: &[IpNet] = if holder.managed || !managed {
                        &holder.routes
                    } else {
                        &[]
                    };
                    holder.interface.iter().chain(routes).copied()
                })
                .collect(),
        )
    }

    /// What `owner` sees of the shared state: the others' holdings and its
    /// own claim. A change notice that leaves it the same, such as one
    /// `owner` caused itself, needs no new look.
    pub fn view(&self, owner: &str) -> (Vec<IpNet>, Vec<IpNet>) {
        let own = self.held(owner);
        (self.others(owner), own)
    }

    /// The subnets `owner` holds, sorted.
    pub fn held(&self, owner: &str) -> Vec<IpNet> {
        self.state()
            .holders
            .get(owner)
            .map(|holder| holder.routes.clone())
            .unwrap_or_default()
    }

    /// `owner` stopped: what it held is free.
    pub fn release(&self, owner: &str) {
        let mut state = self.state();
        if state.holders.remove(owner).is_some() {
            self.changed(&state);
        }
    }

    /// The owner of the most specific virtual range or held subnet that
    /// holds `address` (an IPv4-mapped IPv6 address counts as its IPv4
    /// address). On one prefix a `managed` network's virtual range wins,
    /// then the one that joined first; held subnets never overlap another
    /// network's.
    pub fn lookup(&self, address: IpAddr) -> Option<Arc<str>> {
        let address = canonical(address);
        let table = self
            .inner
            .table
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        table
            .iter()
            .find(|(net, _)| net.contains(address))
            .map(|(_, owner)| owner.clone())
    }

    /// Ticks at every change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).expect("network")
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn claims_compare_as_sets_and_settle() {
        let routes = HostRoutes::default();
        routes.join("mesh-a", true, &[net("10.150.0.0/16")]);
        let mut changes = routes.subscribe();
        assert_eq!(
            routes.claim("mesh-a", &[net("192.168.2.0/24")]),
            [net("192.168.2.0/24")]
        );
        changes.mark_unchanged();
        // A subnet that sorts first arrives; installed in another order.
        let held = routes.claim("mesh-a", &[net("10.20.0.0/16"), net("192.168.2.0/24")]);
        assert_eq!(held, [net("10.20.0.0/16"), net("192.168.2.0/24")]);
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        routes.narrow("mesh-a", &[net("192.168.2.0/24"), net("10.20.0.0/16")]);
        routes.claim("mesh-a", &[net("192.168.2.0/24"), net("10.20.0.0/16")]);
        assert!(!changes.has_changed().unwrap());
        // What failed to install is given up, once.
        routes.narrow("mesh-a", &[net("192.168.2.0/24")]);
        assert!(changes.has_changed().unwrap());
        assert_eq!(routes.view("mesh-a").1, [net("192.168.2.0/24")]);
        // The network's own claims leave what it sees of the others alone.
        assert_eq!(routes.view("mesh-a").0, Vec::<IpNet>::new());
    }

    #[test]
    fn a_managed_network_takes_a_subnet_from_a_legacy_one() {
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[net("10.144.0.0/24")]);
        routes.join("managed", true, &[net("10.150.0.0/16")]);
        // The managed network restarted: the legacy one took the subnet.
        assert_eq!(
            routes.claim("legacy", &[net("192.168.50.0/24")]),
            [net("192.168.50.0/24")]
        );
        let (_, before) = routes.view("legacy");
        assert_eq!(
            routes.claim("managed", &[net("192.168.50.0/24")]),
            [net("192.168.50.0/24")]
        );
        // The legacy network lost it and cannot take it back.
        let (others, own) = routes.view("legacy");
        assert_ne!(own, before);
        assert!(own.is_empty());
        assert!(others.contains(&net("192.168.50.0/24")));
        assert!(routes.claim("legacy", &[net("192.168.50.0/24")]).is_empty());
        // Between networks of one kind the first keeps it.
        routes.join("managed-2", true, &[]);
        assert!(routes
            .claim("managed-2", &[net("192.168.50.0/24")])
            .is_empty());
    }

    #[test]
    fn a_virtual_range_is_never_claimed_by_another_network() {
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[]);
        assert_eq!(
            routes.claim("legacy", &[net("10.150.0.0/16")]),
            [net("10.150.0.0/16")]
        );
        // A network on that range starts: the others see it at once.
        routes.join("managed", true, &[net("10.150.0.5/16")]);
        assert!(routes.others("legacy").contains(&net("10.150.0.0/16")));
        assert!(routes.claim("legacy", &[net("10.150.0.0/16")]).is_empty());
        // Nor by a managed network.
        routes.join("managed-2", true, &[]);
        assert!(routes
            .claim("managed-2", &[net("10.150.1.0/24")])
            .is_empty());
    }

    #[test]
    fn the_first_network_to_claim_a_subnet_keeps_it() {
        let routes = HostRoutes::default();
        let mut changes = routes.subscribe();
        let a = routes.claim("mesh-a", &[net("192.168.50.0/24"), net("172.16.0.0/16")]);
        assert_eq!(a.len(), 2);
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        // Overlapping either way is refused; the rest is taken.
        let b = routes.claim(
            "mesh-b",
            &[
                net("192.168.50.128/25"),
                net("172.0.0.0/8"),
                net("10.9.0.0/16"),
            ],
        );
        assert_eq!(b, [net("10.9.0.0/16")]);
        assert_eq!(routes.others("mesh-b").len(), 2);
        assert!(routes.others("mesh-a").contains(&net("10.9.0.0/16")));
        // Claiming the same again changes nothing.
        changes.mark_unchanged();
        routes.claim("mesh-a", &a);
        assert!(!changes.has_changed().unwrap());
        // Once the first network stops, the subnet is free.
        drop(Claim {
            routes: routes.clone(),
            owner: "mesh-a".into(),
        });
        assert!(changes.has_changed().unwrap());
        let b = routes.claim("mesh-b", &[net("192.168.50.128/25")]);
        assert_eq!(b, [net("192.168.50.128/25")]);
    }

    #[test]
    fn a_managed_network_sees_a_legacy_networks_subnets_as_its_to_take() {
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[net("10.144.0.0/24")]);
        routes.join("managed", true, &[net("10.150.0.0/16")]);
        routes.claim("legacy", &[net("192.168.50.0/24")]);
        // The managed network's node does not refuse the subnet as local,
        // so it wants it and takes it.
        assert_eq!(routes.others("managed"), [net("10.144.0.0/24")]);
        assert!(routes.others("legacy").contains(&net("10.150.0.0/16")));
        routes.claim("managed", &[net("192.168.50.0/24")]);
        assert!(routes.others("legacy").contains(&net("192.168.50.0/24")));
        assert!(routes.held("legacy").is_empty());
    }

    #[test]
    fn a_joining_network_takes_its_virtual_range_back_at_once() {
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[]);
        routes.claim("legacy", &[net("10.150.1.0/24"), net("192.168.1.0/24")]);
        routes.join("managed", true, &[net("10.150.0.5/16")]);
        assert_eq!(routes.held("legacy"), [net("192.168.1.0/24")]);
        assert_eq!(
            routes.lookup(address("10.150.1.9")).as_deref(),
            Some("managed")
        );
    }

    #[test]
    fn an_address_is_looked_up_by_the_most_specific_holding() {
        let routes = HostRoutes::default();
        assert_eq!(routes.lookup(address("10.150.0.9")), None);
        routes.join("a", false, &[net("10.150.0.2/16"), net("fd00:150::2/64")]);
        routes.join("b", false, &[net("10.144.0.2/24")]);
        routes.claim("a", &[net("192.168.10.0/24")]);
        routes.claim("b", &[net("192.168.0.0/16"), net("172.16.5.0/24")]);
        // b's /16 overlaps a's /24: refused.
        assert_eq!(routes.held("b"), [net("172.16.5.0/24")]);
        let owner = |text: &str| routes.lookup(address(text)).map(|owner| owner.to_string());
        assert_eq!(owner("10.150.3.4").as_deref(), Some("a"));
        assert_eq!(owner("10.144.0.7").as_deref(), Some("b"));
        assert_eq!(owner("192.168.10.20").as_deref(), Some("a"));
        assert_eq!(owner("172.16.5.1").as_deref(), Some("b"));
        assert_eq!(owner("fd00:150::9").as_deref(), Some("a"));
        // IPv4-mapped IPv6 addresses count as their IPv4 address.
        assert_eq!(owner("::ffff:10.144.0.7").as_deref(), Some("b"));
        assert_eq!(owner("192.168.11.1"), None);
        assert_eq!(owner("fd00:151::1"), None);
        routes.release("b");
        assert_eq!(owner("172.16.5.1"), None);
        assert_eq!(owner("10.144.0.7"), None);
    }

    #[test]
    fn on_one_virtual_range_the_managed_then_the_earlier_network_is_looked_up() {
        let routes = HostRoutes::default();
        routes.join("legacy-1", false, &[net("10.150.0.2/16")]);
        routes.join("legacy-2", false, &[net("10.150.0.3/16")]);
        assert_eq!(
            routes.lookup(address("10.150.9.9")).as_deref(),
            Some("legacy-1")
        );
        routes.join("managed", true, &[net("10.150.0.4/16")]);
        assert_eq!(
            routes.lookup(address("10.150.9.9")).as_deref(),
            Some("managed")
        );
        // A more specific range still wins.
        routes.join("narrow", false, &[net("10.150.9.1/24")]);
        assert_eq!(
            routes.lookup(address("10.150.9.9")).as_deref(),
            Some("narrow")
        );
    }
}
