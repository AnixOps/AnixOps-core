//! Topology and path choice (spec §12.5, §13).
//!
//! Each node's row lists its direct neighbours; an edge is used only when
//! both ends list each other (spec §12.5). Routes are computed from this
//! node: by fewest hops with relay cost as the second key (spec §13.1), or
//! by lowest latency (spec §13.2). Ties go to the smaller next-hop ID so
//! results are reproducible.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

/// Relay cost of a node that asks not to relay (spec §13.1, §13.2).
pub const AVOID_RELAY_COST: u64 = (1 << 31) - 1;
/// Edge latency when the latency map has none (spec §13.2), milliseconds.
pub const UNKNOWN_LATENCY_MS: u64 = 500;

/// What the topology knows about one node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeEntry {
    pub neighbours: BTreeSet<u32>,
    /// Relay cost from its peer information, normally 1.
    pub cost: u32,
    pub avoid_relay: bool,
}

impl NodeEntry {
    fn relay_cost(&self) -> u64 {
        if self.avoid_relay {
            AVOID_RELAY_COST
        } else {
            u64::from(self.cost)
        }
    }
}

/// One computed route, for forwarding and for the interface (requirement
/// R6): the full path is kept so the status can show which nodes it crosses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub next_hop: u32,
    pub hops: u32,
    /// Sum of relay costs (fewest hops) or of latencies (lowest latency).
    pub metric: u64,
    /// Every node after this one, the destination last.
    pub path: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    Hops,
    Latency,
}

#[derive(Default)]
pub struct Topology {
    nodes: BTreeMap<u32, NodeEntry>,
}

impl Topology {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, peer_id: u32, entry: NodeEntry) {
        self.nodes.insert(peer_id, entry);
    }

    pub fn remove(&mut self, peer_id: u32) {
        self.nodes.remove(&peer_id);
    }

    pub fn get(&self, peer_id: u32) -> Option<&NodeEntry> {
        self.nodes.get(&peer_id)
    }

    /// Whether `a` and `b` list each other.
    pub fn linked(&self, a: u32, b: u32) -> bool {
        let listed = |x: u32, y: u32| {
            self.nodes
                .get(&x)
                .is_some_and(|entry| entry.neighbours.contains(&y))
        };
        listed(a, b) && listed(b, a)
    }

    fn neighbours(&self, node: u32) -> impl Iterator<Item = u32> + '_ {
        self.nodes
            .get(&node)
            .into_iter()
            .flat_map(|entry| entry.neighbours.iter().copied())
            .filter(move |&other| self.linked(node, other))
    }

    /// Routes from `source` to every reachable node. `latency(a, b)` gives
    /// the measured latency of an edge in milliseconds, used with
    /// [`Metric::Latency`].
    pub fn routes(
        &self,
        source: u32,
        metric: Metric,
        latency: impl Fn(u32, u32) -> Option<u64>,
    ) -> BTreeMap<u32, Route> {
        // Key: (primary, secondary, first hop); smaller is better.
        type Key = (u64, u64, u32);
        let mut best: BTreeMap<u32, (Key, u32)> = BTreeMap::new(); // node -> (key, predecessor)
        let mut heap = BinaryHeap::new();
        best.insert(source, ((0, 0, 0), source));
        heap.push(Reverse(((0u64, 0u64, 0u32), source)));

        while let Some(Reverse((key, node))) = heap.pop() {
            if best.get(&node).is_some_and(|(known, _)| *known < key) {
                continue;
            }
            let through = if node == source {
                0
            } else {
                self.nodes.get(&node).map_or(0, NodeEntry::relay_cost)
            };
            for next in self.neighbours(node) {
                if next == source {
                    continue;
                }
                let first_hop = if node == source { next } else { key.2 };
                let candidate = match metric {
                    Metric::Hops => (key.0 + 1, key.1 + through, first_hop),
                    Metric::Latency => {
                        let edge = latency(node, next).unwrap_or(UNKNOWN_LATENCY_MS);
                        (key.0 + edge + through, key.1 + 1, first_hop)
                    }
                };
                let better = best.get(&next).is_none_or(|(known, _)| candidate < *known);
                if better {
                    best.insert(next, (candidate, node));
                    heap.push(Reverse((candidate, next)));
                }
            }
        }

        let mut routes = BTreeMap::new();
        for (&node, &(key, _)) in &best {
            if node == source {
                continue;
            }
            let mut path = vec![node];
            let mut at = node;
            while let Some(&(_, previous)) = best.get(&at) {
                if previous == source {
                    break;
                }
                path.push(previous);
                at = previous;
            }
            path.reverse();
            let (hops, metric_value) = match metric {
                Metric::Hops => (key.0 as u32, key.1),
                Metric::Latency => (key.1 as u32, key.0),
            };
            routes.insert(
                node,
                Route {
                    next_hop: key.2,
                    hops,
                    metric: metric_value,
                    path,
                },
            );
        }
        routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology(edges: &[(u32, u32)]) -> Topology {
        let mut topology = Topology::new();
        for &(a, b) in edges {
            for (x, y) in [(a, b), (b, a)] {
                let entry = topology.nodes.entry(x).or_insert_with(|| NodeEntry {
                    cost: 1,
                    ..NodeEntry::default()
                });
                entry.neighbours.insert(y);
            }
        }
        topology
    }

    #[test]
    fn fewest_hops_with_paths() {
        // 1 - 2 - 3 - 4 and 1 - 5 - 4: 4 is two hops away through 5.
        let topology = topology(&[(1, 2), (2, 3), (3, 4), (1, 5), (5, 4)]);
        let routes = topology.routes(1, Metric::Hops, |_, _| None);
        assert_eq!(
            routes[&2],
            Route {
                next_hop: 2,
                hops: 1,
                metric: 0,
                path: vec![2]
            }
        );
        assert_eq!(routes[&4].next_hop, 5);
        assert_eq!(routes[&4].hops, 2);
        assert_eq!(routes[&4].path, vec![5, 4]);
        assert_eq!(routes[&3].path, vec![2, 3]);
        assert!(!routes.contains_key(&1));
    }

    #[test]
    fn ties_go_to_the_smaller_next_hop() {
        // 1 - 3 - 9 and 1 - 2 - 9.
        let topology = topology(&[(1, 3), (3, 9), (1, 2), (2, 9)]);
        let routes = topology.routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&9].next_hop, 2);
    }

    #[test]
    fn avoid_relay_nodes_are_last_resort() {
        // Two equal-hop paths to 9; relay 2 asks not to relay.
        let mut topology = topology(&[(1, 2), (2, 9), (1, 3), (3, 9)]);
        topology.nodes.get_mut(&2).unwrap().avoid_relay = true;
        let routes = topology.routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&9].next_hop, 3);
        // With no other way, it is still used.
        topology.remove(3);
        topology.nodes.get_mut(&1).unwrap().neighbours.remove(&3);
        topology.nodes.get_mut(&9).unwrap().neighbours.remove(&3);
        let routes = topology.routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&9].next_hop, 2);
        assert_eq!(routes[&9].metric, AVOID_RELAY_COST);
    }

    #[test]
    fn one_sided_edges_are_not_used() {
        let mut topology = topology(&[(1, 2)]);
        topology.nodes.get_mut(&2).unwrap().neighbours.insert(3);
        topology.set(
            3,
            NodeEntry {
                cost: 1,
                ..NodeEntry::default()
            },
        );
        assert!(!topology.linked(2, 3));
        let routes = topology.routes(1, Metric::Hops, |_, _| None);
        assert!(!routes.contains_key(&3));
    }

    #[test]
    fn lowest_latency_prefers_the_faster_detour() {
        // Direct 1 - 4 is slow (300 ms); 1 - 2 - 4 is 10 + 10 plus relay cost 1.
        let topology = topology(&[(1, 4), (1, 2), (2, 4)]);
        let latency = |a: u32, b: u32| match (a.min(b), a.max(b)) {
            (1, 4) => Some(300),
            _ => Some(10),
        };
        let routes = topology.routes(1, Metric::Latency, latency);
        assert_eq!(routes[&4].next_hop, 2);
        assert_eq!(routes[&4].hops, 2);
        assert_eq!(routes[&4].metric, 21);
        // Unknown latencies count as 500 each.
        let routes = topology.routes(1, Metric::Latency, |_, _| None);
        assert_eq!(routes[&4].next_hop, 4);
        assert_eq!(routes[&4].metric, 500);
    }
}
