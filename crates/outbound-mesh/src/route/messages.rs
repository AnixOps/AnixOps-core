//! Route synchronisation messages (spec §2.2, §12.1, §12.3, §12.4).
//!
//! Peer information that is passed on for other nodes keeps its original
//! bytes (spec §12.3), so [`RoutePeerInfo`] holds them next to the decoded
//! fields.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::wire::pb::{PbError, Reader, Writer};

/// A 128-bit identifier (spec §2.2): four big-endian 32-bit groups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        for (i, chunk) in self.0.as_chunks::<4>().0.iter().enumerate() {
            writer.u32(i as u32 + 1, u32::from_be_bytes(*chunk));
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut out = [0u8; 16];
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            if (1..=4).contains(&field) {
                let at = (field as usize - 1) * 4;
                out[at..at + 4].copy_from_slice(&value.u32(field)?.to_be_bytes());
            }
        }
        Ok(Self(out))
    }
}

fn encode_ipv4(address: Ipv4Addr) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u32(1, u32::from(address));
    writer.finish()
}

fn decode_ipv4(message: &[u8]) -> Result<Ipv4Addr, PbError> {
    let mut address = 0;
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        if field == 1 {
            address = value.u32(field)?;
        }
    }
    Ok(Ipv4Addr::from(address))
}

fn encode_ipv6(address: Ipv6Addr) -> Vec<u8> {
    let mut writer = Writer::new();
    for (i, chunk) in address.octets().as_chunks::<4>().0.iter().enumerate() {
        writer.u32(i as u32 + 1, u32::from_be_bytes(*chunk));
    }
    writer.finish()
}

fn decode_ipv6(message: &[u8]) -> Result<Ipv6Addr, PbError> {
    let mut out = [0u8; 16];
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        if (1..=4).contains(&field) {
            let at = (field as usize - 1) * 4;
            out[at..at + 4].copy_from_slice(&value.u32(field)?.to_be_bytes());
        }
    }
    Ok(Ipv6Addr::from(out))
}

/// `Ipv6Inet`: address and prefix length.
fn decode_ipv6_inet(message: &[u8]) -> Result<(Ipv6Addr, u32), PbError> {
    let mut address = Ipv6Addr::UNSPECIFIED;
    let mut prefix = 0;
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => address = decode_ipv6(value.bytes(field)?)?,
            2 => prefix = value.u32(field)?,
            _ => {}
        }
    }
    Ok((address, prefix))
}

fn encode_ipv6_inet(address: Ipv6Addr, prefix: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.message(1, &encode_ipv6(address)).u32(2, prefix);
    writer.finish()
}

/// Feature flags of a node (spec §12.3), all booleans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlags {
    pub is_public_server: bool,
    pub avoid_relay_data: bool,
    pub kcp_input: bool,
    pub no_relay_kcp: bool,
    pub support_conn_list_sync: bool,
    pub quic_input: bool,
    pub no_relay_quic: bool,
    pub is_credential_peer: bool,
    pub need_p2p: bool,
    pub disable_p2p: bool,
    pub ipv6_public_addr_provider: bool,
}

impl FeatureFlags {
    /// What this node announces (spec §12.3): no KCP or QUIC, no direct
    /// connections yet, and a node that does not relay (every access node,
    /// and a full node with `relay: false`) asks not to be used as one.
    /// `relays` is [`crate::config::MeshSettings::relay`].
    pub fn ours(relays: bool) -> Self {
        Self {
            avoid_relay_data: !relays,
            no_relay_kcp: true,
            no_relay_quic: true,
            disable_p2p: true,
            ..Self::default()
        }
    }

    fn bits(&self) -> [bool; 11] {
        [
            self.is_public_server,
            self.avoid_relay_data,
            self.kcp_input,
            self.no_relay_kcp,
            self.support_conn_list_sync,
            self.quic_input,
            self.no_relay_quic,
            self.is_credential_peer,
            self.need_p2p,
            self.disable_p2p,
            self.ipv6_public_addr_provider,
        ]
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        for (i, bit) in self.bits().into_iter().enumerate() {
            writer.bool(i as u32 + 1, bit);
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut flags = Self::default();
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            if !(1..=11).contains(&field) {
                continue;
            }
            let bit = value.bool(field)?;
            match field {
                1 => flags.is_public_server = bit,
                2 => flags.avoid_relay_data = bit,
                3 => flags.kcp_input = bit,
                4 => flags.no_relay_kcp = bit,
                5 => flags.support_conn_list_sync = bit,
                6 => flags.quic_input = bit,
                7 => flags.no_relay_quic = bit,
                8 => flags.is_credential_peer = bit,
                9 => flags.need_p2p = bit,
                10 => flags.disable_p2p = bit,
                11 => flags.ipv6_public_addr_provider = bit,
                _ => {}
            }
        }
        Ok(flags)
    }
}

/// One node's information (spec §12.3). `raw` holds the bytes it was
/// received as, which are what this node forwards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePeerInfo {
    pub peer_id: u32,
    pub inst_id: Uuid,
    pub cost: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub proxy_cidrs: Vec<String>,
    pub hostname: Option<String>,
    pub udp_nat: i32,
    /// Seconds and nanoseconds as sent.
    pub last_update: (i64, i32),
    pub version: u32,
    pub version_string: String,
    pub features: FeatureFlags,
    pub route_id: u64,
    pub network_length: u32,
    pub ipv6: Option<(Ipv6Addr, u32)>,
    pub tcp_nat: i32,
    pub noise_pubkey: Vec<u8>,
    pub raw: Vec<u8>,
}

fn encode_timestamp(seconds: i64, nanos: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.i64(1, seconds).i64(2, i64::from(nanos));
    writer.finish()
}

fn decode_timestamp(message: &[u8]) -> Result<(i64, i32), PbError> {
    let (mut seconds, mut nanos) = (0, 0);
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => seconds = value.i64(field)?,
            2 => nanos = value.i32(field)?,
            _ => {}
        }
    }
    Ok((seconds, nanos))
}

impl RoutePeerInfo {
    /// Encodes this node's own information. Groups, trusted keys and the
    /// public IPv6 fields are never sent.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u32(1, self.peer_id)
            .message(2, &self.inst_id.encode())
            .u32(3, self.cost);
        if let Some(ipv4) = self.ipv4 {
            writer.message(4, &encode_ipv4(ipv4));
        }
        for cidr in &self.proxy_cidrs {
            writer.opt_bytes(5, cidr.as_bytes());
        }
        if let Some(hostname) = &self.hostname {
            writer.opt_bytes(6, hostname.as_bytes());
        }
        writer
            .i64(7, i64::from(self.udp_nat))
            .message(8, &encode_timestamp(self.last_update.0, self.last_update.1))
            .u32(9, self.version)
            .str(10, &self.version_string)
            .message(11, &self.features.encode())
            .u64(12, self.route_id)
            .u32(13, self.network_length);
        if let Some((address, prefix)) = self.ipv6 {
            writer.message(15, &encode_ipv6_inet(address, prefix));
        }
        writer
            .i64(17, i64::from(self.tcp_nat))
            .bytes(18, &self.noise_pubkey);
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut info = RoutePeerInfo {
            raw: message.to_vec(),
            ..Self::default()
        };
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => info.peer_id = value.u32(field)?,
                2 => info.inst_id = Uuid::decode(value.bytes(field)?)?,
                3 => info.cost = value.u32(field)?,
                4 => info.ipv4 = Some(decode_ipv4(value.bytes(field)?)?),
                5 => info.proxy_cidrs.push(value.str(field)?.to_owned()),
                6 => info.hostname = Some(value.str(field)?.to_owned()),
                7 => info.udp_nat = value.i32(field)?,
                8 => info.last_update = decode_timestamp(value.bytes(field)?)?,
                9 => info.version = value.u32(field)?,
                10 => info.version_string = value.str(field)?.to_owned(),
                11 => info.features = FeatureFlags::decode(value.bytes(field)?)?,
                12 => info.route_id = value.u64(field)?,
                13 => info.network_length = value.u32(field)?,
                15 => info.ipv6 = Some(decode_ipv6_inet(value.bytes(field)?)?),
                17 => info.tcp_nat = value.i32(field)?,
                18 => info.noise_pubkey = value.bytes(field)?.to_vec(),
                _ => {}
            }
        }
        Ok(info)
    }
}

/// Most nodes one connection graph may list. The spec sets no limit; ours
/// bounds the work a peer can cause (a bitmap of `n²` bits).
pub const MAX_GRAPH_NODES: usize = 4096;
/// Most edges one connection graph may carry.
pub const MAX_GRAPH_EDGES: usize = 262_144;

/// Which nodes each listed node is directly connected to (spec §12.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnGraph {
    /// Node ID and connection-information version, one per row.
    pub peers: Vec<(u32, u32)>,
    /// `peers[row]` is directly connected to `peers[col]`.
    pub edges: Vec<(usize, usize)>,
}

impl ConnGraph {
    /// The bitmap form (field 5): `N×N` bits, row-major, least significant
    /// bit first in each byte.
    pub fn encode_bitmap(&self) -> Vec<u8> {
        let n = self.peers.len();
        let mut bitmap = vec![0u8; (n * n).div_ceil(8)];
        for &(row, col) in &self.edges {
            let bit = row * n + col;
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
        let mut writer = Writer::new();
        for &(peer_id, version) in &self.peers {
            let mut item = Writer::new();
            item.u32(1, peer_id).u32(2, version);
            writer.message(1, &item.finish());
        }
        writer.bytes(2, &bitmap);
        writer.finish()
    }

    fn decode_peer_version(message: &[u8]) -> Result<(u32, u32), PbError> {
        let (mut peer_id, mut version) = (0, 0);
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => peer_id = value.u32(field)?,
                2 => version = value.u32(field)?,
                _ => {}
            }
        }
        Ok((peer_id, version))
    }

    /// Decodes the bitmap form. A bitmap too short for its node list is
    /// malformed; more than [`MAX_GRAPH_NODES`] nodes or
    /// [`MAX_GRAPH_EDGES`] edges are refused.
    pub fn decode_bitmap(message: &[u8]) -> Result<Self, PbError> {
        let mut peers = Vec::new();
        let mut bitmap: &[u8] = &[];
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => {
                    if peers.len() == MAX_GRAPH_NODES {
                        return Err(PbError::TooMany(1));
                    }
                    peers.push(Self::decode_peer_version(value.bytes(field)?)?);
                }
                2 => bitmap = value.bytes(field)?,
                _ => {}
            }
        }
        let n = peers.len();
        // At most 4096² bits, so this cannot overflow even on 32-bit targets;
        // checked anyway so the bound above is the only assumption.
        let bits = n.checked_mul(n).ok_or(PbError::TooMany(1))?;
        if bitmap.len() < bits.div_ceil(8) {
            return Err(PbError::BadValue(2));
        }
        let mut edges = Vec::new();
        for (index, &byte) in bitmap[..bits.div_ceil(8)].iter().enumerate() {
            let mut byte = byte;
            while byte != 0 {
                let bit = index * 8 + byte.trailing_zeros() as usize;
                byte &= byte - 1;
                if bit >= bits {
                    break;
                }
                if edges.len() == MAX_GRAPH_EDGES {
                    return Err(PbError::TooMany(2));
                }
                edges.push((bit / n, bit % n));
            }
        }
        Ok(Self { peers, edges })
    }

    /// Decodes the list form (field 7): each item names a node and the
    /// nodes it is directly connected to. Neighbours missing from the list
    /// become rows of their own with version 0. The same limits as the
    /// bitmap form apply.
    pub fn decode_list(message: &[u8]) -> Result<Self, PbError> {
        let mut rows: Vec<((u32, u32), Vec<u32>)> = Vec::new();
        let mut edge_count = 0usize;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            if field != 1 {
                continue;
            }
            if rows.len() == MAX_GRAPH_NODES {
                return Err(PbError::TooMany(1));
            }
            let mut head = (0, 0);
            let mut neighbours = Vec::new();
            let mut item = Reader::new(value.bytes(field)?);
            while let Some((f, v)) = item.next()? {
                let mut push = |id: u64| -> Result<(), PbError> {
                    if edge_count == MAX_GRAPH_EDGES {
                        return Err(PbError::TooMany(2));
                    }
                    edge_count += 1;
                    neighbours.push(u32::try_from(id).map_err(|_| PbError::BadValue(2))?);
                    Ok(())
                };
                match (f, v) {
                    (1, v) => head = Self::decode_peer_version(v.bytes(f)?)?,
                    (2, crate::wire::pb::Value::Bytes(packed)) => {
                        // Packed repeated uint32.
                        let mut packed = Reader::new(packed);
                        while let Some(id) = packed.next_varint()? {
                            push(id)?;
                        }
                    }
                    (2, v) => push(u64::from(v.u32(f)?))?,
                    _ => {}
                }
            }
            rows.push((head, neighbours));
        }
        let mut graph = ConnGraph::default();
        let mut positions: HashMap<u32, usize> = HashMap::new();
        let mut index = |graph: &mut ConnGraph, id: u32| -> Result<usize, PbError> {
            if let Some(&i) = positions.get(&id) {
                return Ok(i);
            }
            if graph.peers.len() == MAX_GRAPH_NODES {
                return Err(PbError::TooMany(1));
            }
            graph.peers.push((id, 0));
            positions.insert(id, graph.peers.len() - 1);
            Ok(graph.peers.len() - 1)
        };
        for ((id, version), _) in &rows {
            let i = index(&mut graph, *id)?;
            graph.peers[i].1 = *version;
        }
        for ((id, _), neighbours) in rows {
            let row = index(&mut graph, id)?;
            for neighbour in neighbours {
                let col = index(&mut graph, neighbour)?;
                graph.edges.push((row, col));
            }
        }
        Ok(graph)
    }
}

/// `SyncRouteInfo` request (spec §12.1). Peer information is kept as the
/// raw bytes of each item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncRouteRequest {
    pub my_peer_id: u32,
    pub my_session_id: u64,
    pub is_initiator: bool,
    pub peer_infos: Vec<RoutePeerInfo>,
    pub conn_graph: Option<ConnGraph>,
    /// Field 6, kept as received and passed on unchanged (spec §16.3).
    pub foreign_network_infos: Option<Vec<u8>>,
}

impl SyncRouteRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u32(1, self.my_peer_id)
            .u64(2, self.my_session_id)
            .bool(3, self.is_initiator);
        if !self.peer_infos.is_empty() {
            let mut infos = Writer::new();
            for info in &self.peer_infos {
                let bytes = if info.raw.is_empty() {
                    info.encode()
                } else {
                    info.raw.clone()
                };
                infos.message(1, &bytes);
            }
            writer.message(4, &infos.finish());
        }
        if let Some(graph) = &self.conn_graph {
            writer.message(5, &graph.encode_bitmap());
        }
        if let Some(foreign) = &self.foreign_network_infos {
            writer.message(6, foreign);
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut request = Self::default();
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => request.my_peer_id = value.u32(field)?,
                2 => request.my_session_id = value.u64(field)?,
                3 => request.is_initiator = value.bool(field)?,
                4 => {
                    let mut items = Reader::new(value.bytes(field)?);
                    while let Some((f, v)) = items.next()? {
                        if f == 1 {
                            request.peer_infos.push(RoutePeerInfo::decode(v.bytes(f)?)?);
                        }
                    }
                }
                5 => request.conn_graph = Some(ConnGraph::decode_bitmap(value.bytes(field)?)?),
                7 => {
                    if request.conn_graph.is_none() {
                        request.conn_graph = Some(ConnGraph::decode_list(value.bytes(field)?)?);
                    }
                }
                6 => request.foreign_network_infos = Some(value.bytes(field)?.to_vec()),
                _ => {}
            }
        }
        Ok(request)
    }
}

/// Errors in a `SyncRouteInfo` response (spec §12.1).
pub mod sync_error {
    pub const DUPLICATE_PEER_ID: i32 = 0;
    pub const STOPPED: i32 = 1;
}

/// `SyncRouteInfo` response (spec §12.1); fields 4 and 5 of 2.7.x are
/// ignored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncRouteResponse {
    pub is_initiator: bool,
    pub session_id: u64,
    pub error: Option<i32>,
}

impl SyncRouteResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.bool(1, self.is_initiator).u64(2, self.session_id);
        if let Some(error) = self.error {
            writer.opt_u64(3, error as i64 as u64);
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut response = Self::default();
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => response.is_initiator = value.bool(field)?,
                2 => response.session_id = value.u64(field)?,
                3 => response.error = Some(value.i32(field)?),
                _ => {}
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> RoutePeerInfo {
        RoutePeerInfo {
            peer_id: 7,
            inst_id: Uuid([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            cost: 1,
            ipv4: Some(Ipv4Addr::new(10, 126, 0, 7)),
            proxy_cidrs: vec!["192.168.1.0/24".into()],
            hostname: Some("box".into()),
            udp_nat: 3,
            last_update: (1_700_000_000, 5),
            version: 4,
            version_string: "2.6.4-compat".into(),
            features: FeatureFlags::ours(false),
            route_id: 0xdead_beef_0000_0001,
            network_length: 24,
            ipv6: Some(("fd00::7".parse().unwrap(), 64)),
            tcp_nat: 1,
            noise_pubkey: vec![9; 32],
            raw: Vec::new(),
        }
    }

    #[test]
    fn nodes_that_do_not_relay_say_so() {
        // Access nodes and full nodes with `relay: false` alike.
        assert!(FeatureFlags::ours(false).avoid_relay_data);
        assert!(!FeatureFlags::ours(true).avoid_relay_data);
    }

    #[test]
    fn peer_info_round_trips_and_keeps_raw_bytes() {
        let info = info();
        let bytes = info.encode();
        let decoded = RoutePeerInfo::decode(&bytes).unwrap();
        assert_eq!(decoded.raw, bytes);
        assert_eq!(
            RoutePeerInfo {
                raw: Vec::new(),
                ..decoded
            },
            info
        );
    }

    #[test]
    fn ipv4_is_a_big_endian_integer() {
        // 10.0.0.1 -> 0x0A000001 (spec §2.2).
        assert_eq!(
            encode_ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            [0x08, 0x81, 0x80, 0x80, 0x50]
        );
        assert_eq!(
            decode_ipv4(&[0x08, 0x81, 0x80, 0x80, 0x50]).unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn unknown_fields_survive_forwarding() {
        let mut bytes = info().encode();
        let mut extra = Writer::new();
        extra.opt_bytes(19, b"trusted").opt_u32(22, 1);
        bytes.extend_from_slice(&extra.finish());
        let request = SyncRouteRequest {
            my_peer_id: 1,
            peer_infos: vec![RoutePeerInfo::decode(&bytes).unwrap()],
            ..Default::default()
        };
        let again = SyncRouteRequest::decode(&request.encode()).unwrap();
        assert_eq!(again.peer_infos[0].raw, bytes);
    }

    #[test]
    fn bitmap_layout() {
        let graph = ConnGraph {
            peers: vec![(1, 1), (2, 1), (3, 2)],
            edges: vec![(0, 1), (1, 0), (1, 2), (2, 1)],
        };
        let decoded = ConnGraph::decode_bitmap(&graph.encode_bitmap()).unwrap();
        assert_eq!(decoded, graph);
        // Bits 1, 3, 5, 7 of a 3×3 matrix: one byte 0b1010_1010, then 0.
        let encoded = graph.encode_bitmap();
        let mut reader = Reader::new(&encoded);
        let mut bitmap = Vec::new();
        while let Some((field, value)) = reader.next().unwrap() {
            if field == 2 {
                bitmap = value.bytes(field).unwrap().to_vec();
            }
        }
        assert_eq!(bitmap, [0b1010_1010, 0]);
    }

    #[test]
    fn short_bitmap_is_malformed() {
        let mut writer = Writer::new();
        for id in 1..=3u32 {
            let mut item = Writer::new();
            item.u32(1, id);
            writer.message(1, &item.finish());
        }
        writer.bytes(2, &[0xff]);
        assert!(ConnGraph::decode_bitmap(&writer.finish()).is_err());
    }

    #[test]
    fn graph_limits() {
        // One node too many in the bitmap form, with no bitmap at all: the
        // node count is refused before any n² work.
        let mut writer = Writer::new();
        for id in 0..=MAX_GRAPH_NODES as u32 {
            let mut item = Writer::new();
            item.u32(1, id);
            writer.message(1, &item.finish());
        }
        assert_eq!(
            ConnGraph::decode_bitmap(&writer.finish()),
            Err(PbError::TooMany(1))
        );

        // A full bitmap of 600 nodes has 360,000 edges: above the limit.
        let n = 600usize;
        let mut writer = Writer::new();
        for id in 0..n as u32 {
            let mut item = Writer::new();
            item.u32(1, id);
            writer.message(1, &item.finish());
        }
        writer.bytes(2, &vec![0xff; (n * n).div_ceil(8)]);
        assert_eq!(
            ConnGraph::decode_bitmap(&writer.finish()),
            Err(PbError::TooMany(2))
        );

        // Padding bits past n² are ignored.
        let graph = ConnGraph {
            peers: vec![(1, 1), (2, 1), (3, 1)],
            edges: vec![(2, 2)],
        };
        let mut encoded = Writer::new();
        for &(peer, version) in &graph.peers {
            let mut item = Writer::new();
            item.u32(1, peer).u32(2, version);
            encoded.message(1, &item.finish());
        }
        encoded.bytes(2, &[0, 0xff]);
        assert_eq!(ConnGraph::decode_bitmap(&encoded.finish()).unwrap(), graph);

        // The list form: too many distinct neighbours.
        let mut head = Writer::new();
        head.u32(1, 1);
        let mut item = Writer::new();
        item.message(1, &head.finish());
        let packed: Vec<u8> = (0..=MAX_GRAPH_NODES as u64)
            .flat_map(|id| {
                let mut writer = Writer::new();
                writer.u64(1, id + 2);
                // Strip the tag byte: what remains is the varint.
                writer.finish()[1..].to_vec()
            })
            .collect();
        item.opt_bytes(2, &packed);
        let mut message = Writer::new();
        message.message(1, &item.finish());
        assert_eq!(
            ConnGraph::decode_list(&message.finish()),
            Err(PbError::TooMany(1))
        );
    }

    #[test]
    fn list_form_decodes_packed_and_unpacked() {
        let mut head = Writer::new();
        head.u32(1, 10).u32(2, 3);
        let mut item = Writer::new();
        item.message(1, &head.finish());
        // Packed: neighbours 20 and 30.
        item.opt_bytes(2, &[20, 30]);
        let mut message = Writer::new();
        message.message(1, &item.finish());
        let graph = ConnGraph::decode_list(&message.finish()).unwrap();
        assert_eq!(graph.peers, vec![(10, 3), (20, 0), (30, 0)]);
        assert_eq!(graph.edges, vec![(0, 1), (0, 2)]);
    }

    #[test]
    fn sync_request_and_response_round_trip() {
        let request = SyncRouteRequest {
            my_peer_id: 1,
            my_session_id: 99,
            is_initiator: true,
            peer_infos: vec![info()],
            conn_graph: Some(ConnGraph {
                peers: vec![(1, 1), (7, 1)],
                edges: vec![(0, 1), (1, 0)],
            }),
            foreign_network_infos: Some(vec![0x0a, 0x00]),
        };
        let decoded = SyncRouteRequest::decode(&request.encode()).unwrap();
        assert_eq!(decoded.my_session_id, 99);
        assert!(decoded.is_initiator);
        assert_eq!(decoded.peer_infos[0].peer_id, 7);
        assert_eq!(decoded.conn_graph, request.conn_graph);
        assert_eq!(decoded.foreign_network_infos, request.foreign_network_infos);

        for response in [
            SyncRouteResponse {
                is_initiator: false,
                session_id: 5,
                error: None,
            },
            SyncRouteResponse {
                is_initiator: true,
                session_id: 0,
                error: Some(sync_error::DUPLICATE_PEER_ID),
            },
            SyncRouteResponse {
                is_initiator: false,
                session_id: 1,
                error: Some(sync_error::STOPPED),
            },
        ] {
            assert_eq!(
                SyncRouteResponse::decode(&response.encode()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn uuid_groups_are_big_endian() {
        let uuid = Uuid([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]);
        assert_eq!(uuid.encode(), [0x08, 1, 0x10, 2, 0x18, 3, 0x20, 4]);
        assert_eq!(Uuid::decode(&uuid.encode()).unwrap(), uuid);
    }
}
