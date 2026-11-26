//! Peer RPC packets (spec §11.1–§11.3): one call is split into pieces that
//! each travel in a node packet of type 8 (request) or 9 (response).

use crate::wire::pb::{PbError, Reader, Writer};

/// Largest `body` slice per piece (spec §11.2).
pub const PIECE_BODY: usize = 1000;
/// Most pieces one call may have (spec §11.2).
pub const MAX_PIECES: u32 = 32768;
/// Default timeout of a call, and of reassembly (spec §11.5).
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;
/// Timeout of an empty route synchronisation (spec §11.5); larger ones get
/// more, see [`route_sync_timeout_ms`].
pub const ROUTE_SYNC_TIMEOUT_MS: u32 = 3000;
/// Longest timeout of any call, and of reassembly (spec §11.5).
pub const MAX_TIMEOUT_MS: u32 = 15_000;

/// Timeout of a route synchronisation request of `bytes` encoded bytes,
/// written into its `timeout_ms` (spec §11.5): 3 s plus 2 s per MiB, pro
/// rata, at most 15 s.
pub fn route_sync_timeout_ms(bytes: usize) -> u32 {
    let extra = (bytes as u64).saturating_mul(2000) / (1024 * 1024);
    (u64::from(ROUTE_SYNC_TIMEOUT_MS) + extra).min(u64::from(MAX_TIMEOUT_MS)) as u32
}

/// Reassembly timeout of a request of `total_pieces` pieces (spec §11.5).
/// The request's own `timeout_ms` is known only once it is whole, so the
/// receiver bounds the wait by what a route synchronisation of that size
/// is given: at least [`DEFAULT_TIMEOUT_MS`], at most [`MAX_TIMEOUT_MS`].
pub fn reassembly_timeout_ms(total_pieces: u32) -> u32 {
    route_sync_timeout_ms((total_pieces as usize).saturating_mul(PIECE_BODY))
        .max(DEFAULT_TIMEOUT_MS)
}

/// Compression algorithms (spec §11.3).
pub mod compression {
    pub const NONE: i32 = 1;
    pub const ZSTD: i32 = 2;
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Descriptor {
    /// The network name.
    pub domain: String,
    /// The service name; sent in both name fields (spec §11.1).
    pub service: String,
    /// Starts at 1.
    pub method_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionInfo {
    pub algo: i32,
    pub accepted_algo: i32,
}

impl CompressionInfo {
    /// What this node always sends: nothing compressed, nothing accepted.
    pub const PLAIN: Self = Self {
        algo: compression::NONE,
        accepted_algo: compression::NONE,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcPacket {
    pub from_peer: u32,
    pub to_peer: u32,
    pub transaction_id: i64,
    pub descriptor: Option<Descriptor>,
    pub body: Vec<u8>,
    pub is_request: bool,
    pub total_pieces: u32,
    pub piece_idx: u32,
    pub trace_id: i32,
    pub compression: Option<CompressionInfo>,
}

fn encode_descriptor(descriptor: &Descriptor) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .str(1, &descriptor.domain)
        .str(2, &descriptor.service)
        .str(3, &descriptor.service)
        .u32(4, descriptor.method_index);
    writer.finish()
}

fn decode_descriptor(message: &[u8]) -> Result<Descriptor, PbError> {
    let mut descriptor = Descriptor::default();
    let mut proto_name = String::new();
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => descriptor.domain = value.str(field)?.to_owned(),
            2 => proto_name = value.str(field)?.to_owned(),
            3 => descriptor.service = value.str(field)?.to_owned(),
            4 => descriptor.method_index = value.u32(field)?,
            _ => {}
        }
    }
    if descriptor.service.is_empty() {
        descriptor.service = proto_name;
    }
    Ok(descriptor)
}

fn encode_compression(info: &CompressionInfo) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .i64(1, i64::from(info.algo))
        .i64(2, i64::from(info.accepted_algo));
    writer.finish()
}

fn decode_compression(message: &[u8]) -> Result<CompressionInfo, PbError> {
    let mut info = CompressionInfo {
        algo: 0,
        accepted_algo: 0,
    };
    let mut reader = Reader::new(message);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => info.algo = value.i32(field)?,
            2 => info.accepted_algo = value.i32(field)?,
            _ => {}
        }
    }
    Ok(info)
}

impl RpcPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u32(1, self.from_peer)
            .u32(2, self.to_peer)
            .i64(3, self.transaction_id);
        if let Some(descriptor) = &self.descriptor {
            writer.message(4, &encode_descriptor(descriptor));
        }
        writer
            .bytes(5, &self.body)
            .bool(6, self.is_request)
            .u32(7, self.total_pieces)
            .u32(8, self.piece_idx)
            .i64(9, i64::from(self.trace_id));
        if let Some(info) = &self.compression {
            writer.message(10, &encode_compression(info));
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut packet = RpcPacket {
            from_peer: 0,
            to_peer: 0,
            transaction_id: 0,
            descriptor: None,
            body: Vec::new(),
            is_request: false,
            total_pieces: 0,
            piece_idx: 0,
            trace_id: 0,
            compression: None,
        };
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => packet.from_peer = value.u32(field)?,
                2 => packet.to_peer = value.u32(field)?,
                3 => packet.transaction_id = value.i64(field)?,
                4 => packet.descriptor = Some(decode_descriptor(value.bytes(field)?)?),
                5 => packet.body = value.bytes(field)?.to_vec(),
                6 => packet.is_request = value.bool(field)?,
                7 => packet.total_pieces = value.u32(field)?,
                8 => packet.piece_idx = value.u32(field)?,
                9 => packet.trace_id = value.i32(field)?,
                10 => packet.compression = Some(decode_compression(value.bytes(field)?)?),
                _ => {}
            }
        }
        Ok(packet)
    }

    /// Whether the piece numbering is usable (spec §11.2).
    pub fn pieces_valid(&self) -> bool {
        self.total_pieces >= 1
            && self.total_pieces <= MAX_PIECES
            && self.piece_idx < self.total_pieces
    }
}

/// Splits one call body into pieces (spec §11.2). The descriptor goes in
/// every piece (nothing is compressed); compression information only in the
/// first.
pub fn split(
    from_peer: u32,
    to_peer: u32,
    transaction_id: i64,
    descriptor: &Descriptor,
    is_request: bool,
    body: &[u8],
) -> Vec<RpcPacket> {
    let chunks: Vec<&[u8]> = if body.is_empty() {
        vec![&[][..]]
    } else {
        body.chunks(PIECE_BODY).collect()
    };
    let total = chunks.len() as u32;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| RpcPacket {
            from_peer,
            to_peer,
            transaction_id,
            descriptor: Some(descriptor.clone()),
            body: chunk.to_vec(),
            is_request,
            total_pieces: total,
            piece_idx: index as u32,
            trace_id: 0,
            compression: (index == 0).then_some(CompressionInfo::PLAIN),
        })
        .collect()
}

/// `RpcRequest` (spec §11.1): field 1 is obsolete and never sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcRequest {
    pub request: Vec<u8>,
    pub timeout_ms: i32,
}

impl RpcRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .bytes(2, &self.request)
            .i64(3, i64::from(self.timeout_ms));
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut out = RpcRequest {
            request: Vec::new(),
            timeout_ms: 0,
        };
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                2 => out.request = value.bytes(field)?.to_vec(),
                3 => out.timeout_ms = value.i32(field)?,
                _ => {}
            }
        }
        Ok(out)
    }
}

/// RPC errors (spec §11.1). This node only produces the first four kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcError {
    Other(String),
    InvalidMethod,
    InvalidService,
    Decode,
    Encode,
    Execution,
    Malformed,
    Timeout,
}

impl RpcError {
    fn field(&self) -> u32 {
        match self {
            RpcError::Other(_) => 1,
            RpcError::InvalidMethod => 2,
            RpcError::InvalidService => 3,
            RpcError::Decode => 4,
            RpcError::Encode => 5,
            RpcError::Execution => 6,
            RpcError::Malformed => 7,
            RpcError::Timeout => 8,
        }
    }
}

/// `RpcResponse` (spec §11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcResponse {
    pub result: Result<Vec<u8>, RpcError>,
    pub runtime_us: u64,
}

impl RpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        match &self.result {
            Ok(response) => {
                writer.bytes(1, response);
            }
            Err(error) => {
                // Each variant is a message; only Other carries a string.
                let mut inner = Writer::new();
                if let RpcError::Other(text) = error {
                    inner.str(1, text);
                }
                let mut error_message = Writer::new();
                error_message.message(error.field(), &inner.finish());
                writer.message(2, &error_message.finish());
            }
        }
        writer.u64(3, self.runtime_us);
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, PbError> {
        let mut response = Vec::new();
        let mut error = None;
        let mut runtime_us = 0;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => response = value.bytes(field)?.to_vec(),
                2 => {
                    let mut inner = Reader::new(value.bytes(field)?);
                    if let Some((kind, body)) = inner.next()? {
                        error = Some(match kind {
                            1 => {
                                let mut text = String::new();
                                let mut fields = Reader::new(body.bytes(kind)?);
                                while let Some((f, v)) = fields.next()? {
                                    if f == 1 {
                                        text = v.str(f)?.to_owned();
                                    }
                                }
                                RpcError::Other(text)
                            }
                            2 => RpcError::InvalidMethod,
                            3 => RpcError::InvalidService,
                            4 => RpcError::Decode,
                            5 => RpcError::Encode,
                            6 => RpcError::Execution,
                            7 => RpcError::Malformed,
                            8 => RpcError::Timeout,
                            _ => RpcError::Other(String::new()),
                        });
                    }
                }
                3 => runtime_us = value.u64(field)?,
                _ => {}
            }
        }
        Ok(Self {
            result: match error {
                Some(error) => Err(error),
                None => Ok(response),
            },
            runtime_us,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Descriptor {
        Descriptor {
            domain: "office".into(),
            service: "OspfRouteRpc".into(),
            method_index: 1,
        }
    }

    #[test]
    fn packet_round_trips() {
        let packet = RpcPacket {
            from_peer: 1,
            to_peer: 2,
            transaction_id: -5,
            descriptor: Some(descriptor()),
            body: vec![1, 2, 3],
            is_request: true,
            total_pieces: 1,
            piece_idx: 0,
            trace_id: -1,
            compression: Some(CompressionInfo::PLAIN),
        };
        assert_eq!(RpcPacket::decode(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn descriptor_falls_back_to_proto_name() {
        let mut writer = Writer::new();
        writer.str(1, "office").str(2, "PeerCenterRpc").u32(4, 2);
        let descriptor = decode_descriptor(&writer.finish()).unwrap();
        assert_eq!(descriptor.service, "PeerCenterRpc");
        assert_eq!(descriptor.method_index, 2);
    }

    #[test]
    fn split_pieces_and_limits() {
        let body: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let pieces = split(1, 2, 9, &descriptor(), true, &body);
        assert_eq!(pieces.len(), 3);
        assert!(pieces
            .iter()
            .all(|p| p.total_pieces == 3 && p.descriptor.is_some()));
        assert!(pieces[0].compression.is_some() && pieces[1].compression.is_none());
        let joined: Vec<u8> = pieces.iter().flat_map(|p| p.body.clone()).collect();
        assert_eq!(joined, body);
        // Encoded pieces stay within the 1300-byte datagram budget with a
        // 16-byte header and the AEAD tail.
        for piece in &pieces {
            assert!(piece.encode().len() + 16 + 28 <= 1300);
        }
        let empty = split(1, 2, 9, &descriptor(), false, &[]);
        assert_eq!(empty.len(), 1);
        assert!(empty[0].pieces_valid());

        let mut bad = pieces[0].clone();
        bad.total_pieces = 0;
        assert!(!bad.pieces_valid());
        bad.total_pieces = MAX_PIECES + 1;
        assert!(!bad.pieces_valid());
        bad.total_pieces = 3;
        bad.piece_idx = 3;
        assert!(!bad.pieces_valid());
    }

    #[test]
    fn request_and_response_round_trip() {
        let request = RpcRequest {
            request: vec![9; 4],
            timeout_ms: 3000,
        };
        assert_eq!(RpcRequest::decode(&request.encode()).unwrap(), request);
        for result in [
            Ok(vec![1, 2]),
            Ok(Vec::new()),
            Err(RpcError::Other("boom".into())),
            Err(RpcError::InvalidMethod),
            Err(RpcError::InvalidService),
            Err(RpcError::Decode),
            Err(RpcError::Timeout),
        ] {
            let response = RpcResponse {
                result,
                runtime_us: 12,
            };
            assert_eq!(RpcResponse::decode(&response.encode()).unwrap(), response);
        }
    }

    #[test]
    fn route_sync_timeouts_grow_with_size_up_to_fifteen_seconds() {
        const MIB: usize = 1024 * 1024;
        assert_eq!(route_sync_timeout_ms(0), 3000);
        assert_eq!(route_sync_timeout_ms(MIB / 2), 4000);
        assert_eq!(route_sync_timeout_ms(MIB), 5000);
        assert_eq!(route_sync_timeout_ms(4 * MIB), 11_000);
        assert_eq!(route_sync_timeout_ms(6 * MIB), 15_000);
        assert_eq!(route_sync_timeout_ms(usize::MAX), MAX_TIMEOUT_MS);
        // Reassembly: never under the default, never over the top.
        assert_eq!(reassembly_timeout_ms(1), DEFAULT_TIMEOUT_MS);
        assert_eq!(
            reassembly_timeout_ms(2098),
            route_sync_timeout_ms(2_098_000)
        );
        assert!(reassembly_timeout_ms(2098) > DEFAULT_TIMEOUT_MS);
        assert_eq!(reassembly_timeout_ms(MAX_PIECES), MAX_TIMEOUT_MS);
    }
}
