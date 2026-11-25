//! Reassembly of RPC pieces (spec §11.2) with the limits of spec §19.3:
//! at most [`MAX_PENDING_PER_PEER`] calls per peer in progress, each
//! dropped after its timeout. Calls are keyed by the peer the session layer
//! received them from, never by what a piece claims, and the whole
//! reassembler is bounded by [`MAX_PENDING_TOTAL`] calls and
//! [`MAX_TOTAL_BYTES`].

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::packet::{Descriptor, RpcPacket};

/// Most calls one peer may have in reassembly at once (spec §19.3).
pub const MAX_PENDING_PER_PEER: usize = 16;
/// Most bytes one call may reassemble to.
pub const MAX_CALL_BYTES: usize = 4 * 1024 * 1024;
/// Most calls in progress across all peers.
pub const MAX_PENDING_TOTAL: usize = 256;
/// Most bytes held across all calls in progress.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// A whole call, ready to dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub from_peer: u32,
    pub transaction_id: i64,
    pub is_request: bool,
    pub descriptor: Descriptor,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Bad piece numbering, or a piece inconsistent with earlier ones.
    Malformed,
    /// The peer, or the node as a whole, already has too many calls in
    /// progress.
    TooMany,
    /// The piece claims to come from another peer than the one it arrived
    /// from.
    WrongSource,
    /// The call would exceed [`MAX_CALL_BYTES`].
    TooLarge,
    /// No descriptor in the first piece.
    NoDescriptor,
}

struct Pending {
    total: u32,
    is_request: bool,
    descriptor: Option<Descriptor>,
    pieces: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
    deadline: Instant,
}

#[derive(Default)]
pub struct Reassembler {
    pending: BTreeMap<(u32, i64, bool), Pending>,
    bytes: usize,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one piece that arrived from `source`, the peer the session
    /// layer authenticated as the packet's origin; returns the call once
    /// every piece is in.
    pub fn push(
        &mut self,
        source: u32,
        piece: RpcPacket,
        timeout: Duration,
        now: Instant,
    ) -> Result<Option<Call>, Dropped> {
        if piece.from_peer != source {
            return Err(Dropped::WrongSource);
        }
        if !piece.pieces_valid() {
            return Err(Dropped::Malformed);
        }
        let key = (source, piece.transaction_id, piece.is_request);
        if !self.pending.contains_key(&key) {
            let in_progress = self
                .pending
                .keys()
                .filter(|(from, _, _)| *from == source)
                .count();
            if in_progress >= MAX_PENDING_PER_PEER || self.pending.len() >= MAX_PENDING_TOTAL {
                return Err(Dropped::TooMany);
            }
        }
        let pending = self.pending.entry(key).or_insert_with(|| Pending {
            total: piece.total_pieces,
            is_request: piece.is_request,
            descriptor: None,
            pieces: BTreeMap::new(),
            bytes: 0,
            deadline: now + timeout,
        });
        if pending.total != piece.total_pieces {
            self.remove(&key);
            return Err(Dropped::Malformed);
        }
        if pending.descriptor.is_none() {
            pending.descriptor = piece.descriptor;
        }
        if !pending.pieces.contains_key(&piece.piece_idx) {
            let len = piece.body.len();
            if pending.bytes + len > MAX_CALL_BYTES || self.bytes + len > MAX_TOTAL_BYTES {
                self.remove(&key);
                return Err(Dropped::TooLarge);
            }
            pending.bytes += len;
            self.bytes += len;
            pending.pieces.insert(piece.piece_idx, piece.body);
        }
        if pending.pieces.len() < pending.total as usize {
            return Ok(None);
        }
        let pending = self.remove(&key).expect("present");
        let descriptor = pending.descriptor.ok_or(Dropped::NoDescriptor)?;
        Ok(Some(Call {
            from_peer: key.0,
            transaction_id: key.1,
            is_request: pending.is_request,
            descriptor,
            body: pending.pieces.into_values().flatten().collect(),
        }))
    }

    fn remove(&mut self, key: &(u32, i64, bool)) -> Option<Pending> {
        let pending = self.pending.remove(key)?;
        self.bytes -= pending.bytes;
        Some(pending)
    }

    /// Drops calls past their deadline; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        let mut freed = 0;
        self.pending.retain(|_, pending| {
            let keep = pending.deadline > now;
            if !keep {
                freed += pending.bytes;
            }
            keep
        });
        self.bytes -= freed;
        before - self.pending.len()
    }

    /// Bytes held by calls in progress.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn in_progress(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::packet::split;

    fn descriptor() -> Descriptor {
        Descriptor {
            domain: "office".into(),
            service: "OspfRouteRpc".into(),
            method_index: 1,
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn reassembles_out_of_order_and_ignores_duplicates() {
        let body: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let mut pieces = split(4, 1, 77, &descriptor(), true, &body);
        pieces.reverse();
        let duplicate = pieces[0].clone();
        pieces.insert(1, duplicate);
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let mut done = None;
        for piece in pieces {
            if let Some(call) = reassembler.push(4, piece, TIMEOUT, now).unwrap() {
                done = Some(call);
            }
        }
        let call = done.unwrap();
        assert_eq!(call.body, body);
        assert_eq!(call.from_peer, 4);
        assert_eq!(call.transaction_id, 77);
        assert!(call.is_request);
        assert_eq!(call.descriptor, descriptor());
        assert_eq!(reassembler.in_progress(), 0);
    }

    #[test]
    fn requests_and_responses_with_one_id_are_separate() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let request = split(4, 1, 5, &descriptor(), true, b"req").remove(0);
        let response = split(4, 1, 5, &descriptor(), false, b"resp").remove(0);
        assert!(
            reassembler
                .push(4, request, TIMEOUT, now)
                .unwrap()
                .unwrap()
                .is_request
        );
        assert!(
            !reassembler
                .push(4, response, TIMEOUT, now)
                .unwrap()
                .unwrap()
                .is_request
        );
    }

    #[test]
    fn limits_and_malformed_pieces() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let body = vec![0u8; 1500];
        for id in 0..MAX_PENDING_PER_PEER as i64 {
            let first = split(4, 1, id, &descriptor(), true, &body).remove(0);
            assert_eq!(reassembler.push(4, first, TIMEOUT, now), Ok(None));
        }
        let one_more = split(4, 1, 99, &descriptor(), true, &body).remove(0);
        assert_eq!(
            reassembler.push(4, one_more.clone(), TIMEOUT, now),
            Err(Dropped::TooMany)
        );
        // Another peer is not affected.
        let mut other = one_more;
        other.from_peer = 5;
        assert_eq!(reassembler.push(5, other, TIMEOUT, now), Ok(None));

        let mut bad = split(4, 1, 0, &descriptor(), true, &body).remove(1);
        bad.total_pieces = 3;
        assert_eq!(
            reassembler.push(4, bad, TIMEOUT, now),
            Err(Dropped::Malformed)
        );
        let mut bad = split(6, 1, 0, &descriptor(), true, b"x").remove(0);
        bad.piece_idx = 1;
        assert_eq!(
            reassembler.push(6, bad, TIMEOUT, now),
            Err(Dropped::Malformed)
        );

        let mut no_descriptor = split(6, 1, 1, &descriptor(), true, b"x").remove(0);
        no_descriptor.descriptor = None;
        assert_eq!(
            reassembler.push(6, no_descriptor, TIMEOUT, now),
            Err(Dropped::NoDescriptor)
        );
    }

    #[test]
    fn pieces_are_keyed_by_the_receiving_session() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let piece = split(4, 1, 1, &descriptor(), true, b"x").remove(0);
        assert_eq!(
            reassembler.push(5, piece, TIMEOUT, now),
            Err(Dropped::WrongSource)
        );
    }

    #[test]
    fn total_calls_and_bytes_are_bounded() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let body = vec![0u8; 1500];
        // 16 calls from each of 16 peers fill the node-wide limit.
        for peer in 0..(MAX_PENDING_TOTAL / MAX_PENDING_PER_PEER) as u32 {
            for id in 0..MAX_PENDING_PER_PEER as i64 {
                let first = split(peer, 1, id, &descriptor(), true, &body).remove(0);
                assert_eq!(reassembler.push(peer, first, TIMEOUT, now), Ok(None));
            }
        }
        let first = split(999, 1, 0, &descriptor(), true, &body).remove(0);
        assert_eq!(
            reassembler.push(999, first, TIMEOUT, now),
            Err(Dropped::TooMany)
        );
        assert!(reassembler.bytes() > 0);
        assert_eq!(reassembler.expire(now + TIMEOUT), MAX_PENDING_TOTAL);
        assert_eq!(reassembler.bytes(), 0);
    }

    #[test]
    fn expires_incomplete_calls() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let first = split(4, 1, 1, &descriptor(), true, &[0; 1500]).remove(0);
        reassembler.push(4, first, TIMEOUT, now).unwrap();
        assert_eq!(reassembler.expire(now + Duration::from_secs(1)), 0);
        assert_eq!(reassembler.expire(now + TIMEOUT), 1);
        assert_eq!(reassembler.in_progress(), 0);
    }
}
