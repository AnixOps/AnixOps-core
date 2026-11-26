//! Reassembly of RPC pieces (spec §11.2) with the limits of spec §19.3:
//! at most [`MAX_PENDING_PER_PEER`] calls per peer in progress, each
//! dropped after its timeout. Calls are keyed by the peer the session layer
//! received them from, never by what a piece claims, and the whole
//! reassembler is bounded by [`MAX_PENDING_TOTAL`] calls and
//! [`MAX_TOTAL_BYTES`]. One peer may hold at most [`MAX_PEER_BYTES`], a
//! quarter of the total, so no single peer can crowd out the calls of the
//! others (route synchronisation among them). When a few peers together
//! fill the total, the one holding the most loses its largest call to make
//! room for a lighter peer.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::packet::{Descriptor, RpcPacket};

/// Most calls one peer may have in reassembly at once (spec §19.3).
pub const MAX_PENDING_PER_PEER: usize = 16;
/// Most bytes one call may reassemble to (spec §11.2): the largest full
/// synchronisation, a 2 MiB graph and 4095 node informations.
pub const MAX_CALL_BYTES: usize = 8 * 1024 * 1024;
/// Most calls in progress across all peers.
pub const MAX_PENDING_TOTAL: usize = 256;
/// Most bytes held across all calls in progress.
pub const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
/// Most bytes one peer's calls in progress may hold together.
pub const MAX_PEER_BYTES: usize = MAX_TOTAL_BYTES / 4;

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
    /// The peer would exceed [`MAX_PEER_BYTES`] or the node
    /// [`MAX_TOTAL_BYTES`].
    TooLarge,
    /// The call would exceed [`MAX_CALL_BYTES`] (spec §11.2): dropped, and
    /// the node raises the alert for an oversized synchronisation. Carries
    /// the bytes the call had reached.
    CallTooLarge(usize),
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
        let (in_progress, peer_bytes) = self
            .pending
            .range((source, i64::MIN, false)..=(source, i64::MAX, true))
            .fold((0, 0), |(calls, bytes), (_, pending)| {
                (calls + 1, bytes + pending.bytes)
            });
        if !self.pending.contains_key(&key)
            && (in_progress >= MAX_PENDING_PER_PEER || self.pending.len() >= MAX_PENDING_TOTAL)
        {
            return Err(Dropped::TooMany);
        }
        let len = piece.body.len();
        let existing = self.pending.get(&key).map(|pending| {
            (
                pending.total,
                pending.bytes,
                pending.pieces.contains_key(&piece.piece_idx),
            )
        });
        let (call_bytes, new_piece) = match existing {
            Some((total, _, _)) if total != piece.total_pieces => {
                self.remove(&key);
                return Err(Dropped::Malformed);
            }
            Some((_, bytes, held)) => (bytes, !held),
            None => (0, true),
        };
        if new_piece {
            if call_bytes + len > MAX_CALL_BYTES {
                self.remove(&key);
                return Err(Dropped::CallTooLarge(call_bytes + len));
            }
            let fits = peer_bytes + len <= MAX_PEER_BYTES
                && (self.bytes + len <= MAX_TOTAL_BYTES || self.make_room(source, peer_bytes, len));
            if !fits {
                self.remove(&key);
                return Err(Dropped::TooLarge);
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
        if pending.descriptor.is_none() {
            pending.descriptor = piece.descriptor;
        }
        if new_piece {
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

    /// Frees room for `len` more bytes from `source`, which holds
    /// `source_bytes`, when the node-wide budget is full: the peer holding
    /// the most loses its largest call, as long as it holds more than
    /// `source` would. Returns whether the room was made.
    fn make_room(&mut self, source: u32, source_bytes: usize, len: usize) -> bool {
        while self.bytes + len > MAX_TOTAL_BYTES {
            let mut per_peer: BTreeMap<u32, usize> = BTreeMap::new();
            for (&(peer, _, _), pending) in &self.pending {
                *per_peer.entry(peer).or_default() += pending.bytes;
            }
            let Some((&heaviest, &held)) = per_peer.iter().max_by_key(|(_, held)| **held) else {
                return false;
            };
            if heaviest == source || held <= source_bytes + len {
                return false;
            }
            let largest = self
                .pending
                .iter()
                .filter(|((peer, _, _), _)| *peer == heaviest)
                .max_by_key(|(_, pending)| pending.bytes)
                .map(|(key, _)| *key);
            match largest {
                Some(key) => {
                    self.remove(&key);
                }
                None => return false,
            }
        }
        true
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
    fn one_peer_cannot_take_the_whole_budget() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let body = vec![0u8; MAX_PEER_BYTES * 3 / 4];
        // All but the last piece of a large call stay in reassembly.
        let mut first = split(4, 1, 1, &descriptor(), true, &body);
        first.pop();
        for piece in first {
            assert_eq!(reassembler.push(4, piece, TIMEOUT, now), Ok(None));
        }
        let mut refused = None;
        for piece in split(4, 1, 2, &descriptor(), true, &body) {
            if let Err(dropped) = reassembler.push(4, piece, TIMEOUT, now) {
                refused = Some(dropped);
                break;
            }
        }
        assert_eq!(refused, Some(Dropped::TooLarge));
        assert!(reassembler.bytes() <= MAX_PEER_BYTES);
        // Another peer still gets through.
        let other = split(5, 1, 1, &descriptor(), true, b"route");
        assert!(reassembler
            .push(5, other[0].clone(), TIMEOUT, now)
            .unwrap()
            .is_some());
    }

    #[test]
    fn peers_that_fill_the_total_make_room_for_a_lighter_one() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let body = vec![0u8; MAX_PEER_BYTES - 64];
        let peers = (MAX_TOTAL_BYTES / MAX_PEER_BYTES) as u32;
        for peer in 1..=peers {
            let mut pieces = split(peer, 1, 1, &descriptor(), true, &body);
            pieces.pop();
            for piece in pieces {
                assert_eq!(reassembler.push(peer, piece, TIMEOUT, now), Ok(None));
            }
        }
        let full = reassembler.in_progress();
        assert_eq!(full, peers as usize);

        // A light peer's route call still gets through, at the cost of one
        // heavy call.
        let route = vec![1u8; 20_000];
        let mut done = None;
        for piece in split(50, 1, 1, &descriptor(), true, &route) {
            if let Some(call) = reassembler.push(50, piece, TIMEOUT, now).unwrap() {
                done = Some(call);
            }
        }
        assert_eq!(done.unwrap().body, route);
        assert_eq!(reassembler.in_progress(), full - 1);
        assert!(reassembler.bytes() <= MAX_TOTAL_BYTES);

        // The heaviest peer cannot push others out the same way.
        let mut pieces = split(1, 1, 2, &descriptor(), true, &route);
        pieces.pop();
        let refused = pieces
            .into_iter()
            .find_map(|piece| reassembler.push(1, piece, TIMEOUT, now).err());
        assert_eq!(refused, Some(Dropped::TooLarge));
        assert!(reassembler.bytes() <= MAX_TOTAL_BYTES);
    }

    #[test]
    fn a_call_over_the_limit_is_reported_apart_from_budgets() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let body = vec![0u8; MAX_CALL_BYTES + 1];
        let refused = split(4, 1, 1, &descriptor(), true, &body)
            .into_iter()
            .find_map(|piece| reassembler.push(4, piece, TIMEOUT, now).err());
        match refused {
            Some(Dropped::CallTooLarge(bytes)) => assert!(bytes > MAX_CALL_BYTES),
            other => panic!("{other:?}"),
        }
        // Nothing of it is kept, and a call at the limit still completes.
        assert_eq!(reassembler.bytes(), 0);
        let body = vec![1u8; MAX_CALL_BYTES];
        let mut done = None;
        for piece in split(4, 1, 2, &descriptor(), true, &body) {
            if let Some(call) = reassembler.push(4, piece, TIMEOUT, now).unwrap() {
                done = Some(call);
            }
        }
        assert_eq!(done.unwrap().body.len(), MAX_CALL_BYTES);
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
