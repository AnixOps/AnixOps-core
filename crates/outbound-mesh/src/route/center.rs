//! The latency centre (spec §13.3): every node reports its direct
//! neighbours' latencies to the centre, the node with the smallest ID among
//! the reachable non-shared nodes, and fetches the whole latency map from it.
//! Both node roles run the centre service, since either may be the smallest.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::legacy::keys::siphash13;
use crate::wire::pb::{PbError, Reader, Writer};

/// How often a node reports, at the latest (spec §13.3).
pub const REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// How often a node fetches the global map (spec §13.3).
pub const FETCH_INTERVAL: Duration = Duration::from_secs(15);
/// The centre drops a node not heard from for this long (spec §13.3).
pub const ENTRY_TTL: Duration = Duration::from_secs(180);
/// Most nodes the centre keeps; reports from further nodes are dropped.
pub const MAX_ENTRIES: usize = 4096;
/// Most neighbours one report may list; the rest are dropped.
pub const MAX_REPORTED_PEERS: usize = 1024;

/// Service name and method numbers (spec §11.4).
pub const SERVICE: &str = "PeerCenterRpc";
pub const METHOD_REPORT_PEERS: u32 = 1;
pub const METHOD_GET_GLOBAL_PEER_MAP: u32 = 2;

/// A node's direct neighbours and their latency in milliseconds.
pub type PeerMap = BTreeMap<u32, i32>;

fn encode_peer_map(map: &PeerMap) -> Vec<u8> {
    let mut writer = Writer::new();
    for (&peer, &latency) in map {
        let mut value = Writer::new();
        value.i64(1, i64::from(latency));
        let mut entry = Writer::new();
        entry.u32(1, peer).message(2, &value.finish());
        writer.message(1, &entry.finish());
    }
    writer.finish()
}

fn decode_peer_map(message: &[u8]) -> Result<PeerMap, PbError> {
    let mut map = PeerMap::new();
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        if field != 1 {
            continue;
        }
        let (mut key, mut latency) = (0, 0);
        let mut entry = Reader::new(value.bytes(field)?);
        while let Some((f, v)) = entry.next()? {
            match f {
                1 => key = v.u32(f)?,
                2 => {
                    let mut inner = Reader::new(v.bytes(f)?);
                    while let Some((g, w)) = inner.next()? {
                        if g == 1 {
                            latency = w.i32(g)?;
                        }
                    }
                }
                _ => {}
            }
        }
        map.insert(key, latency);
    }
    Ok(map)
}

/// `ReportPeers` request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportPeers {
    pub my_peer_id: u32,
    pub peers: PeerMap,
}

impl ReportPeers {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u32(1, self.my_peer_id)
            .message(2, &encode_peer_map(&self.peers));
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut out = Self::default();
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => out.my_peer_id = value.u32(field)?,
                2 => out.peers = decode_peer_map(value.bytes(field)?)?,
                _ => {}
            }
        }
        Ok(out)
    }
}

/// `GetGlobalPeerMap` request: the digest last received, 0 the first time.
pub fn encode_get_request(digest: u64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u64(1, digest);
    writer.finish()
}

pub fn decode_get_request(message: &[u8]) -> Result<u64, PbError> {
    let mut digest = 0;
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        if field == 1 {
            digest = value.u64(field)?;
        }
    }
    Ok(digest)
}

/// `GetGlobalPeerMap` response. An unchanged map comes back empty and
/// without a digest; the caller keeps its copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GlobalPeerMap {
    pub map: BTreeMap<u32, PeerMap>,
    pub digest: Option<u64>,
}

impl GlobalPeerMap {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        for (&peer, map) in &self.map {
            let mut entry = Writer::new();
            entry.u32(1, peer).message(2, &encode_peer_map(map));
            writer.message(1, &entry.finish());
        }
        if let Some(digest) = self.digest {
            writer.opt_u64(2, digest);
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut out = Self::default();
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => {
                    let (mut key, mut map) = (0, PeerMap::new());
                    let mut entry = Reader::new(value.bytes(field)?);
                    while let Some((f, v)) = entry.next()? {
                        match f {
                            1 => key = v.u32(f)?,
                            2 => map = decode_peer_map(v.bytes(f)?)?,
                            _ => {}
                        }
                    }
                    out.map.insert(key, map);
                }
                2 => out.digest = Some(value.u64(field)?),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The centre among `candidates` (reachable nodes that are not shared
/// nodes, this node included): the smallest ID.
pub fn centre(candidates: impl IntoIterator<Item = u32>) -> Option<u32> {
    candidates.into_iter().min()
}

/// The centre service's state.
#[derive(Default)]
pub struct CentreServer {
    entries: BTreeMap<u32, (PeerMap, Instant)>,
    cached_digest: std::sync::Mutex<Option<u64>>,
}

impl CentreServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a report. Returns `false` when the centre is full and the
    /// node is new; a report listing more than [`MAX_REPORTED_PEERS`]
    /// neighbours keeps the first ones only.
    pub fn report(&mut self, report: ReportPeers, now: Instant) -> bool {
        if !self.entries.contains_key(&report.my_peer_id) && self.entries.len() >= MAX_ENTRIES {
            return false;
        }
        let peers = report.peers.into_iter().take(MAX_REPORTED_PEERS).collect();
        self.entries.insert(report.my_peer_id, (peers, now));
        *self.cached_digest.lock().unwrap_or_else(|e| e.into_inner()) = None;
        true
    }

    /// Drops nodes not heard from for [`ENTRY_TTL`].
    pub fn expire(&mut self, now: Instant) {
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < ENTRY_TTL);
        if self.entries.len() != before {
            *self.cached_digest.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// Our own digest of the map; callers treat it as opaque.
    pub fn digest(&self) -> u64 {
        if let Some(d) = *self.cached_digest.lock().unwrap_or_else(|e| e.into_inner()) {
            return d;
        }
        let mut bytes = Vec::new();
        for (&peer, (map, _)) in &self.entries {
            bytes.extend_from_slice(&peer.to_le_bytes());
            bytes.extend_from_slice(&encode_peer_map(map));
            bytes.push(0xff);
        }
        // Zero means "nothing yet" to callers, so never hand it out.
        let d = siphash13(&bytes).max(1);
        *self.cached_digest.lock().unwrap_or_else(|e| e.into_inner()) = Some(d);
        d
    }

    /// Answers `GetGlobalPeerMap`.
    pub fn get(&self, known_digest: u64) -> GlobalPeerMap {
        let digest = self.digest();
        if known_digest == digest {
            return GlobalPeerMap::default();
        }
        GlobalPeerMap {
            map: self
                .entries
                .iter()
                .map(|(&peer, (map, _))| (peer, map.clone()))
                .collect(),
            digest: Some(digest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(peer: u32, entries: &[(u32, i32)]) -> ReportPeers {
        ReportPeers {
            my_peer_id: peer,
            peers: entries.iter().copied().collect(),
        }
    }

    #[test]
    fn messages_round_trip() {
        let request = report(5, &[(6, 12), (7, -1)]);
        assert_eq!(ReportPeers::decode(&request.encode()).unwrap(), request);
        assert_eq!(decode_get_request(&encode_get_request(0)).unwrap(), 0);
        assert_eq!(decode_get_request(&encode_get_request(42)).unwrap(), 42);
        let response = GlobalPeerMap {
            map: [(5, request.peers.clone())].into_iter().collect(),
            digest: Some(9),
        };
        assert_eq!(GlobalPeerMap::decode(&response.encode()).unwrap(), response);
        assert_eq!(
            GlobalPeerMap::decode(&[]).unwrap(),
            GlobalPeerMap::default()
        );
    }

    #[test]
    fn centre_is_the_smallest_id() {
        assert_eq!(centre([9, 3, 7]), Some(3));
        assert_eq!(centre([]), None);
    }

    #[test]
    fn server_answers_changes_only() {
        let start = Instant::now();
        let mut server = CentreServer::new();
        server.report(report(1, &[(2, 10)]), start);
        let first = server.get(0);
        let digest = first.digest.unwrap();
        assert_eq!(first.map.len(), 1);
        // Unchanged: empty and no digest.
        assert_eq!(server.get(digest), GlobalPeerMap::default());
        server.report(report(2, &[(1, 11)]), start);
        let second = server.get(digest);
        assert_eq!(second.map.len(), 2);
        assert_ne!(second.digest, Some(digest));
    }

    #[test]
    fn server_is_bounded() {
        let now = Instant::now();
        let mut server = CentreServer::new();
        for peer in 0..MAX_ENTRIES as u32 {
            assert!(server.report(report(peer, &[]), now));
        }
        assert!(!server.report(report(u32::MAX, &[]), now));
        // A known node may still report.
        assert!(server.report(report(0, &[(1, 5)]), now));
        let many: Vec<(u32, i32)> = (0..2000).map(|peer| (peer, 1)).collect();
        assert!(server.report(report(1, &many), now));
        assert_eq!(server.get(0).map[&1].len(), MAX_REPORTED_PEERS);
    }

    #[test]
    fn server_forgets_silent_nodes() {
        let start = Instant::now();
        let mut server = CentreServer::new();
        server.report(report(1, &[]), start);
        server.report(report(2, &[]), start + Duration::from_secs(100));
        server.expire(start + ENTRY_TTL);
        assert_eq!(
            server.get(0).map.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
    }
}
