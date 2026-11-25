//! Reassembly of RPC pieces (spec §11.2) with the limits of spec §19.3:
//! at most [`MAX_PENDING_PER_PEER`] calls per peer in progress, each
//! dropped after its timeout.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::packet::{Descriptor, RpcPacket};

/// Most calls one peer may have in reassembly at once (spec §19.3).
pub const MAX_PENDING_PER_PEER: usize = 16;
/// Most bytes one call may reassemble to.
pub const MAX_CALL_BYTES: usize = 4 * 1024 * 1024;

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
    /// The peer already has too many calls in progress.
    TooMany,
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
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one piece; returns the call once every piece is in.
    pub fn push(
        &mut self,
        piece: RpcPacket,
        timeout: Duration,
        now: Instant,
    ) -> Result<Option<Call>, Dropped> {
        if !piece.pieces_valid() {
            return Err(Dropped::Malformed);
        }
        let key = (piece.from_peer, piece.transaction_id, piece.is_request);
        if !self.pending.contains_key(&key) {
            let in_progress = self
                .pending
                .keys()
                .filter(|(from, _, _)| *from == piece.from_peer)
                .count();
            if in_progress >= MAX_PENDING_PER_PEER {
                return Err(Dropped::TooMany);
            }
            self.pending.insert(
                key,
                Pending {
                    total: piece.total_pieces,
                    is_request: piece.is_request,
                    descriptor: None,
                    pieces: BTreeMap::new(),
                    bytes: 0,
                    deadline: now + timeout,
                },
            );
        }
        let pending = self.pending.get_mut(&key).expect("inserted above");
        if pending.total != piece.total_pieces {
            self.pending.remove(&key);
            return Err(Dropped::Malformed);
        }
        if pending.descriptor.is_none() {
            pending.descriptor = piece.descriptor;
        }
        if !pending.pieces.contains_key(&piece.piece_idx) {
            pending.bytes += piece.body.len();
            if pending.bytes > MAX_CALL_BYTES {
                self.pending.remove(&key);
                return Err(Dropped::TooLarge);
            }
            pending.pieces.insert(piece.piece_idx, piece.body);
        }
        if pending.pieces.len() < pending.total as usize {
            return Ok(None);
        }
        let pending = self.pending.remove(&key).expect("present");
        let descriptor = pending.descriptor.ok_or(Dropped::NoDescriptor)?;
        Ok(Some(Call {
            from_peer: key.0,
            transaction_id: key.1,
            is_request: pending.is_request,
            descriptor,
            body: pending.pieces.into_values().flatten().collect(),
        }))
    }

    /// Drops calls past their deadline; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, pending| pending.deadline > now);
        before - self.pending.len()
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
            if let Some(call) = reassembler.push(piece, TIMEOUT, now).unwrap() {
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
                .push(request, TIMEOUT, now)
                .unwrap()
                .unwrap()
                .is_request
        );
        assert!(
            !reassembler
                .push(response, TIMEOUT, now)
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
            assert_eq!(reassembler.push(first, TIMEOUT, now), Ok(None));
        }
        let one_more = split(4, 1, 99, &descriptor(), true, &body).remove(0);
        assert_eq!(
            reassembler.push(one_more.clone(), TIMEOUT, now),
            Err(Dropped::TooMany)
        );
        // Another peer is not affected.
        let mut other = one_more;
        other.from_peer = 5;
        assert_eq!(reassembler.push(other, TIMEOUT, now), Ok(None));

        let mut bad = split(4, 1, 0, &descriptor(), true, &body).remove(1);
        bad.total_pieces = 3;
        assert_eq!(reassembler.push(bad, TIMEOUT, now), Err(Dropped::Malformed));
        let mut bad = split(6, 1, 0, &descriptor(), true, b"x").remove(0);
        bad.piece_idx = 1;
        assert_eq!(reassembler.push(bad, TIMEOUT, now), Err(Dropped::Malformed));

        let mut no_descriptor = split(6, 1, 1, &descriptor(), true, b"x").remove(0);
        no_descriptor.descriptor = None;
        assert_eq!(
            reassembler.push(no_descriptor, TIMEOUT, now),
            Err(Dropped::NoDescriptor)
        );
    }

    #[test]
    fn expires_incomplete_calls() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let first = split(4, 1, 1, &descriptor(), true, &[0; 1500]).remove(0);
        reassembler.push(first, TIMEOUT, now).unwrap();
        assert_eq!(reassembler.expire(now + Duration::from_secs(1)), 0);
        assert_eq!(reassembler.expire(now + TIMEOUT), 1);
        assert_eq!(reassembler.in_progress(), 0);
    }
}
