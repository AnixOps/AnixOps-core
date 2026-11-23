//! Reassembly of fragmented UDP datagrams, IPv4 and IPv6.
//!
//! An app that sends a UDP datagram larger than the TUN MTU without Don't
//! Fragment (a SIP INVITE, IKE with certificates, a large DNS or game
//! message) has it split by the kernel before it reaches the stack. Each fragment is a valid IP packet, but only the first one
//! carries the UDP header, and its length field counts the whole datagram,
//! so the UDP socket can read none of them alone. [`Reassembler`] holds the
//! fragments of each datagram until it is whole and hands it on as one IP
//! packet, as a host does (RFC 1122 §3.3.2, RFC 8200 §4.5). Fragments of
//! other protocols are dropped: TCP sizes its segments to the path, and the
//! smoltcp interface refuses fragments anyway.
//!
//! Memory is bounded. At most [`MAX_DATAGRAMS`] datagrams and [`MAX_BYTES`]
//! of fragments are held at once, the oldest datagram making room for a new
//! one, and a datagram still missing fragments [`TIMEOUT`] after its first
//! one came is dropped. Fragments that overlap (RFC 5722) or disagree about
//! the end drop their whole datagram; a fragment that is empty, reaches past
//! the largest IP packet or, before the last one, is not a multiple of 8
//! bytes long is dropped alone. [`StackStats::ip_fragments_dropped`] counts
//! every fragment dropped.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, IPV6_HEADER_LEN};

use crate::{
    packet::{AnyIpPktFrame, IpPacket},
    stats::StackStats,
};

/// Datagrams reassembled at once; a new one beyond this drops the oldest.
pub(crate) const MAX_DATAGRAMS: usize = 32;

/// Fragment bytes held at once, each fragment charged [`FRAGMENT_OVERHEAD`]
/// on top; a fragment beyond this drops the oldest datagrams first. A
/// datagram is at most 64 KiB, so a few of the largest fit.
pub(crate) const MAX_BYTES: usize = 256 * 1024;

/// What holding one fragment costs besides its bytes, so that a flood of
/// tiny fragments meets [`MAX_BYTES`] as well.
pub(crate) const FRAGMENT_OVERHEAD: usize = 64;

/// How long a datagram waits for its missing fragments, from its first
/// fragment on: the reassembly timer RFC 791 recommends. The kernel hands
/// the fragments of a datagram over back to back, so a datagram still
/// waiting this long has lost one.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(15);

/// The largest IP packet: the IPv4 total length, the IPv6 payload length.
const MAX_PACKET: usize = u16::MAX as usize;

/// The IPv6 Fragment header: next header, reserved, fragment offset and M
/// flag, identification (RFC 8200 §4.5).
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

/// Tells the datagrams apart: addresses and identification (RFC 791, RFC
/// 8200 §4.5). Only UDP is joined, so the IPv4 protocol needs no place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
}

/// One fragment of a UDP datagram, borrowed from its packet.
pub(crate) struct Fragment<'a> {
    key: Key,
    /// Where `data` belongs in the datagram, in bytes.
    offset: usize,
    /// Whether fragments follow; unset on the last one.
    more: bool,
    /// The header to rebuild the whole datagram with, should this be its
    /// first fragment: the IPv4 header with its options, or the IPv6
    /// header.
    header: &'a [u8],
    data: &'a [u8],
}

/// What a packet from the TUN side is to reassembly.
pub(crate) enum Piece<'a> {
    /// A whole packet; it goes on as it is.
    Whole,
    /// A fragment of a UDP datagram, for [`Reassembler::push`].
    Udp(Fragment<'a>),
    /// A fragment that is never joined: of TCP or ICMP, or with its IPv6
    /// Fragment header cut short. It is dropped ([`Reassembler::refuse`]).
    Other,
}

/// Sorts out `packet`, a checked packet whose bytes are `frame`.
///
/// An IPv6 fragment is recognised by a Fragment header right after the IPv6
/// header, where the kernel puts it for UDP; a packet with other extension
/// headers first is not UDP to the stack either way.
pub(crate) fn classify<'a>(frame: &'a [u8], packet: &IpPacket<&'a [u8]>) -> Piece<'a> {
    match packet {
        IpPacket::Ipv4(ip) => {
            if !ip.more_frags() && ip.frag_offset() == 0 {
                return Piece::Whole;
            }
            if ip.next_header() != IpProtocol::Udp {
                return Piece::Other;
            }
            Piece::Udp(Fragment {
                key: Key {
                    src: IpAddr::V4(ip.src_addr()),
                    dst: IpAddr::V4(ip.dst_addr()),
                    id: u32::from(ip.ident()),
                },
                offset: usize::from(ip.frag_offset()),
                more: ip.more_frags(),
                header: &frame[..usize::from(ip.header_len())],
                data: ip.payload(),
            })
        }
        IpPacket::Ipv6(ip) => {
            if ip.next_header() != IpProtocol::Ipv6Frag {
                return Piece::Whole;
            }
            let payload = ip.payload();
            if payload.len() < IPV6_FRAGMENT_HEADER_LEN
                || IpProtocol::from(payload[0]) != IpProtocol::Udp
            {
                return Piece::Other;
            }
            // The offset counts 8-byte units in the top 13 bits and the M
            // flag is the lowest bit, so clearing the 3 low bits leaves the
            // offset in bytes.
            let field = u16::from_be_bytes([payload[2], payload[3]]);
            Piece::Udp(Fragment {
                key: Key {
                    src: IpAddr::V6(ip.src_addr()),
                    dst: IpAddr::V6(ip.dst_addr()),
                    id: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
                },
                offset: usize::from(field & !0b111),
                more: field & 1 != 0,
                header: &frame[..IPV6_HEADER_LEN],
                data: &payload[IPV6_FRAGMENT_HEADER_LEN..],
            })
        }
    }
}

/// A datagram being reassembled.
struct Datagram {
    key: Key,
    /// When its first fragment came.
    started: Instant,
    /// The header to rebuild it with, once the fragment at offset 0 came.
    header: Option<Vec<u8>>,
    /// The fragments held, by offset; none overlaps another.
    pieces: Vec<(usize, Vec<u8>)>,
    /// The bytes held in `pieces`.
    held: usize,
    /// The datagram's length, once its last fragment came.
    end: Option<usize>,
    /// What it is charged against [`MAX_BYTES`].
    cost: usize,
}

/// What [`Datagram::add`] did with a fragment.
enum Added {
    /// Holds it.
    New,
    /// The same bytes at the same offset are held already: left out.
    Duplicate,
    /// It overlaps another fragment or disagrees about the end.
    Conflict,
}

impl Datagram {
    fn new(key: Key, now: Instant) -> Self {
        Self {
            key,
            started: now,
            header: None,
            pieces: Vec::new(),
            held: 0,
            end: None,
            cost: 0,
        }
    }

    fn add(&mut self, fragment: &Fragment<'_>) -> Added {
        let start = fragment.offset;
        let end = start + fragment.data.len();
        match self.end {
            Some(total) if end > total || (!fragment.more && end != total) => {
                return Added::Conflict;
            }
            None if !fragment.more => {
                // Nothing held may reach past the end; the last piece
                // reaches furthest.
                let reach = self
                    .pieces
                    .last()
                    .map_or(0, |(offset, data)| offset + data.len());
                if reach > end {
                    return Added::Conflict;
                }
            }
            _ => {}
        }
        let index = self.pieces.partition_point(|(offset, _)| *offset < start);
        if let Some((offset, data)) = self.pieces.get(index) {
            if *offset == start && data.as_slice() == fragment.data {
                return Added::Duplicate;
            }
            if end > *offset {
                return Added::Conflict;
            }
        }
        if let Some((offset, data)) = index.checked_sub(1).and_then(|i| self.pieces.get(i)) {
            if offset + data.len() > start {
                return Added::Conflict;
            }
        }
        if start == 0 {
            self.header = Some(fragment.header.to_vec());
        }
        if !fragment.more {
            self.end = Some(end);
        }
        self.pieces.insert(index, (start, fragment.data.to_vec()));
        self.held += fragment.data.len();
        Added::New
    }

    /// Whether every byte up to the end came. The pieces never overlap and
    /// never reach past the end, so counting them is enough.
    fn is_complete(&self) -> bool {
        self.end == Some(self.held)
    }

    /// The whole datagram as one IP packet: the first fragment's header,
    /// rewritten as unfragmented, then the fragments in order. `None` when
    /// it does not fit in one IP packet.
    fn into_packet(self) -> Option<AnyIpPktFrame> {
        let mut packet = self.header?;
        let end = self.end?;
        packet.reserve_exact(end);
        for (_, data) in &self.pieces {
            packet.extend_from_slice(data);
        }
        match self.key.src {
            IpAddr::V4(_) => {
                let total = u16::try_from(packet.len()).ok()?;
                let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
                ip.set_total_len(total);
                ip.set_more_frags(false);
                ip.set_frag_offset(0);
                ip.fill_checksum();
            }
            IpAddr::V6(_) => {
                let payload_len = u16::try_from(end).ok()?;
                let mut ip = Ipv6Packet::new_unchecked(&mut packet[..]);
                ip.set_payload_len(payload_len);
                ip.set_next_header(IpProtocol::Udp);
            }
        }
        Some(packet)
    }
}

/// Joins UDP datagrams from their fragments; see the module docs.
pub(crate) struct Reassembler {
    datagrams: Vec<Datagram>,
    /// What the datagrams are charged against [`MAX_BYTES`].
    bytes: usize,
    stats: Arc<StackStats>,
}

impl Reassembler {
    pub(crate) fn new(stats: Arc<StackStats>) -> Self {
        Self {
            datagrams: Vec::new(),
            bytes: 0,
            stats,
        }
    }

    /// Holds `fragment` for its datagram, and returns the datagram as one IP
    /// packet once this was its last missing fragment.
    pub(crate) fn push(&mut self, fragment: Fragment<'_>, now: Instant) -> Option<AnyIpPktFrame> {
        self.expire(now);
        let len = fragment.data.len();
        if len == 0
            || fragment.offset + len > MAX_PACKET
            || (fragment.more && !len.is_multiple_of(8))
        {
            // Malformed: dropped alone, like a lost fragment.
            self.stats.count_ip_fragments_dropped(1);
            return None;
        }
        let cost = len + FRAGMENT_OVERHEAD;
        // Older datagrams make room; one that cannot fit alone is dropped.
        while self.bytes + cost > MAX_BYTES {
            let Some(oldest) = self.oldest(Some(fragment.key)) else {
                break;
            };
            self.discard(oldest);
        }
        if self.bytes + cost > MAX_BYTES {
            if let Some(index) = self.position(fragment.key) {
                self.discard(index);
            }
            self.stats.count_ip_fragments_dropped(1);
            return None;
        }
        let index = match self.position(fragment.key) {
            Some(index) => index,
            None => {
                if self.datagrams.len() >= MAX_DATAGRAMS {
                    if let Some(oldest) = self.oldest(None) {
                        self.discard(oldest);
                    }
                }
                self.datagrams.push(Datagram::new(fragment.key, now));
                self.datagrams.len() - 1
            }
        };
        let datagram = &mut self.datagrams[index];
        match datagram.add(&fragment) {
            Added::New => {
                datagram.cost += cost;
                self.bytes += cost;
            }
            Added::Duplicate => {
                self.stats.count_ip_fragments_dropped(1);
                return None;
            }
            Added::Conflict => {
                self.discard(index);
                self.stats.count_ip_fragments_dropped(1);
                return None;
            }
        }
        if !self.datagrams[index].is_complete() {
            return None;
        }
        let datagram = self.datagrams.swap_remove(index);
        self.bytes -= datagram.cost;
        let fragments = datagram.pieces.len();
        match datagram.into_packet() {
            Some(packet) => {
                self.stats.count_udp_reassembled();
                Some(packet)
            }
            None => {
                self.stats.count_ip_fragments_dropped(fragments);
                None
            }
        }
    }

    /// Counts a fragment dropped without being held: a [`Piece::Other`], or
    /// a UDP fragment while the stack passes no UDP on.
    pub(crate) fn refuse(&self) {
        self.stats.count_ip_fragments_dropped(1);
    }

    /// Drops the datagrams that have waited longer than [`TIMEOUT`].
    fn expire(&mut self, now: Instant) {
        let mut index = 0;
        while index < self.datagrams.len() {
            if now.saturating_duration_since(self.datagrams[index].started) > TIMEOUT {
                self.discard(index);
            } else {
                index += 1;
            }
        }
    }

    fn position(&self, key: Key) -> Option<usize> {
        self.datagrams
            .iter()
            .position(|datagram| datagram.key == key)
    }

    /// The datagram whose first fragment came first, leaving out `except`.
    fn oldest(&self, except: Option<Key>) -> Option<usize> {
        self.datagrams
            .iter()
            .enumerate()
            .filter(|(_, datagram)| Some(datagram.key) != except)
            .min_by_key(|(_, datagram)| datagram.started)
            .map(|(index, _)| index)
    }

    /// Drops a datagram with every fragment it holds.
    fn discard(&mut self, index: usize) {
        let datagram = self.datagrams.swap_remove(index);
        self.bytes -= datagram.cost;
        self.stats.count_ip_fragments_dropped(datagram.pieces.len());
    }
}

/// Packets the tests of this crate send through the stack.
#[cfg(test)]
pub(crate) mod testing {
    use etherparse::PacketBuilder;
    use smoltcp::wire::{Ipv4Packet, IPV6_HEADER_LEN};

    pub(crate) const APP4: [u8; 4] = [10, 0, 0, 2];
    pub(crate) const DNS4: [u8; 4] = [10, 0, 0, 53];
    pub(crate) const APP6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    pub(crate) const DNS6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53];

    /// A UDP datagram from port 5353 of [`APP4`] to port 53 of [`DNS4`], as
    /// one IPv4 packet with identification `id` and without Don't Fragment:
    /// what the kernel holds before it splits a datagram.
    pub(crate) fn udp4(payload: &[u8], id: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP4, DNS4, 64)
            .udp(5353, 53)
            .write(&mut packet, payload)
            .unwrap();
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
        ip.set_ident(id);
        ip.set_dont_frag(false);
        ip.fill_checksum();
        packet
    }

    /// The same datagram between [`APP6`] and [`DNS6`], as one IPv6 packet.
    pub(crate) fn udp6(payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv6(APP6, DNS6, 64)
            .udp(5353, 53)
            .write(&mut packet, payload)
            .unwrap();
        packet
    }

    /// `packet`, an IPv4 packet without options, split as the kernel splits
    /// it: `chunk` bytes of its payload (a multiple of 8) per fragment, in
    /// order.
    pub(crate) fn fragments4(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let payload = &packet[20..];
        let count = payload.len().div_ceil(chunk);
        payload
            .chunks(chunk)
            .enumerate()
            .map(|(index, piece)| {
                let mut fragment = packet[..20].to_vec();
                fragment.extend_from_slice(piece);
                let mut ip = Ipv4Packet::new_unchecked(&mut fragment[..]);
                ip.set_total_len((20 + piece.len()) as u16);
                ip.set_more_frags(index + 1 < count);
                ip.set_frag_offset((index * chunk) as u16);
                ip.fill_checksum();
                fragment
            })
            .collect()
    }

    /// `packet`, an IPv6 packet without extension headers, split as the
    /// kernel splits it: a Fragment header with identification `id` after
    /// the IPv6 header, then `chunk` bytes of its payload (a multiple of 8)
    /// per fragment, in order.
    pub(crate) fn fragments6(packet: &[u8], id: u32, chunk: usize) -> Vec<Vec<u8>> {
        let next_header = packet[6];
        let payload = &packet[IPV6_HEADER_LEN..];
        let count = payload.len().div_ceil(chunk);
        payload
            .chunks(chunk)
            .enumerate()
            .map(|(index, piece)| {
                let mut fragment = packet[..IPV6_HEADER_LEN].to_vec();
                fragment[4..6].copy_from_slice(&((8 + piece.len()) as u16).to_be_bytes());
                fragment[6] = 44;
                // The offset in bytes is a multiple of 8, so it is already
                // shifted into place; the M flag is the lowest bit.
                let field = (index * chunk) as u16 | u16::from(index + 1 < count);
                fragment.extend_from_slice(&[next_header, 0]);
                fragment.extend_from_slice(&field.to_be_bytes());
                fragment.extend_from_slice(&id.to_be_bytes());
                fragment.extend_from_slice(piece);
                fragment
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{fragments4, fragments6, udp4, udp6};
    use super::*;

    fn fresh() -> (Reassembler, Arc<StackStats>) {
        let stats = Arc::new(StackStats::default());
        (Reassembler::new(stats.clone()), stats)
    }

    /// What the stack does with `frame`: the packet that goes on, if any.
    fn offer(reassembler: &mut Reassembler, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        let packet = IpPacket::new_checked(frame).unwrap();
        match classify(frame, &packet) {
            Piece::Whole => Some(frame.to_vec()),
            Piece::Udp(fragment) => reassembler.push(fragment, now),
            Piece::Other => {
                reassembler.refuse();
                None
            }
        }
    }

    #[test]
    fn whole_packets_pass_untouched() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        let packet = udp4(b"query", 1);
        assert_eq!(
            offer(&mut reassembler, &packet, now).as_deref(),
            Some(&packet[..])
        );
        let packet = udp6(b"query");
        assert_eq!(
            offer(&mut reassembler, &packet, now).as_deref(),
            Some(&packet[..])
        );
        assert!(reassembler.datagrams.is_empty());
        assert_eq!(stats.ip_fragments_dropped(), 0);
        assert_eq!(stats.udp_reassembled(), 0);
    }

    #[test]
    fn ipv4_fragments_are_joined_in_any_order() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        let whole = udp4(&[7; 3000], 0x1234);
        let fragments = fragments4(&whole, 1480);
        assert_eq!(fragments.len(), 3);
        assert_eq!(offer(&mut reassembler, &fragments[2], now), None);
        assert_eq!(offer(&mut reassembler, &fragments[0], now), None);
        // The rebuilt packet is the one the kernel split: the first
        // fragment's header with the whole length, no fragment flags and a
        // fresh checksum.
        assert_eq!(offer(&mut reassembler, &fragments[1], now), Some(whole));
        assert_eq!(stats.udp_reassembled(), 1);
        assert_eq!(stats.ip_fragments_dropped(), 0);
        assert!(reassembler.datagrams.is_empty());
        assert_eq!(reassembler.bytes, 0);
    }

    #[test]
    fn ipv6_fragments_are_joined_in_any_order() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        let whole = udp6(&[9; 3000]);
        let fragments = fragments6(&whole, 0xdead_beef, 1232);
        assert_eq!(fragments.len(), 3);
        assert_eq!(offer(&mut reassembler, &fragments[1], now), None);
        assert_eq!(offer(&mut reassembler, &fragments[2], now), None);
        assert_eq!(offer(&mut reassembler, &fragments[0], now), Some(whole));
        assert_eq!(stats.udp_reassembled(), 1);
        assert!(reassembler.datagrams.is_empty());
    }

    #[test]
    fn an_atomic_ipv6_fragment_is_a_whole_datagram() {
        let (mut reassembler, _stats) = fresh();
        let whole = udp6(b"query");
        // One fragment at offset 0 with no more to come (RFC 6946).
        let fragments = fragments6(&whole, 7, 1232);
        assert_eq!(fragments.len(), 1);
        assert_eq!(
            offer(&mut reassembler, &fragments[0], Instant::now()),
            Some(whole)
        );
    }

    #[test]
    fn copies_are_left_out_and_overlaps_drop_the_datagram() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        let whole = udp4(&[1; 2000], 0x1000);
        let fragments = fragments4(&whole, 1480);
        assert_eq!(offer(&mut reassembler, &fragments[0], now), None);
        // The same fragment again changes nothing.
        assert_eq!(offer(&mut reassembler, &fragments[0], now), None);
        assert_eq!(stats.ip_fragments_dropped(), 1);
        assert_eq!(offer(&mut reassembler, &fragments[1], now), Some(whole));

        // A fragment that overlaps another drops the whole datagram (RFC
        // 5722): the held first fragment and the overlapping one.
        let other = udp4(&[2; 2000], 0x2000);
        let fragments = fragments4(&other, 1480);
        let shifted = fragments4(&other, 1472);
        assert_eq!(offer(&mut reassembler, &fragments[0], now), None);
        assert_eq!(offer(&mut reassembler, &shifted[1], now), None);
        assert_eq!(stats.ip_fragments_dropped(), 3);
        assert!(reassembler.datagrams.is_empty());
        assert_eq!(reassembler.bytes, 0);
        // What comes after starts over and never completes alone.
        assert_eq!(offer(&mut reassembler, &fragments[1], now), None);
        assert_eq!(reassembler.datagrams.len(), 1);
        assert_eq!(stats.udp_reassembled(), 1);
    }

    #[test]
    fn other_protocols_and_malformed_fragments_are_dropped() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        // A fragment of TCP.
        let mut tcp = udp4(&[0; 64], 9);
        let mut ip = Ipv4Packet::new_unchecked(&mut tcp[..]);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_more_frags(true);
        ip.fill_checksum();
        assert_eq!(offer(&mut reassembler, &tcp, now), None);
        // An IPv6 fragment of TCP.
        let mut tcp6 = fragments6(&udp6(&[0; 3000]), 11, 1232).remove(0);
        tcp6[IPV6_HEADER_LEN] = 6;
        assert_eq!(offer(&mut reassembler, &tcp6, now), None);
        // A fragment before the last whose length is not a multiple of 8.
        let mut odd = udp4(&[0; 61], 10);
        let mut ip = Ipv4Packet::new_unchecked(&mut odd[..]);
        ip.set_more_frags(true);
        ip.fill_checksum();
        assert_eq!(offer(&mut reassembler, &odd, now), None);
        // A fragment reaching past the largest IP packet.
        let mut far = udp4(&[0; 8], 12);
        let mut ip = Ipv4Packet::new_unchecked(&mut far[..]);
        ip.set_frag_offset(65528);
        ip.fill_checksum();
        assert_eq!(offer(&mut reassembler, &far, now), None);
        assert_eq!(stats.ip_fragments_dropped(), 4);
        assert!(reassembler.datagrams.is_empty());
    }

    #[test]
    fn datagrams_time_out() {
        let (mut reassembler, stats) = fresh();
        let start = Instant::now();
        let fragments = fragments4(&udp4(&[3; 2000], 0x3000), 1480);
        assert_eq!(offer(&mut reassembler, &fragments[0], start), None);
        // The rest comes too late: the first fragment was dropped meanwhile.
        let late = start + TIMEOUT + Duration::from_secs(1);
        assert_eq!(offer(&mut reassembler, &fragments[1], late), None);
        assert_eq!(stats.ip_fragments_dropped(), 1);
        assert_eq!(reassembler.datagrams.len(), 1);
        assert_eq!(stats.udp_reassembled(), 0);
    }

    #[test]
    fn the_oldest_datagram_makes_room_for_a_new_one() {
        let (mut reassembler, stats) = fresh();
        let start = Instant::now();
        // One datagram more than the limit, each missing its last fragment.
        let datagrams: Vec<Vec<Vec<u8>>> = (0..=MAX_DATAGRAMS as u16)
            .map(|id| fragments4(&udp4(&[4; 2000], id), 1480))
            .collect();
        for (index, fragments) in datagrams.iter().enumerate() {
            let now = start + Duration::from_millis(index as u64);
            assert_eq!(offer(&mut reassembler, &fragments[0], now), None);
        }
        assert_eq!(reassembler.datagrams.len(), MAX_DATAGRAMS);
        assert_eq!(stats.ip_fragments_dropped(), 1);
        let now = start + Duration::from_secs(1);
        assert_eq!(
            offer(&mut reassembler, &datagrams[1][1], now),
            Some(udp4(&[4; 2000], 1))
        );
        // The first datagram made room: its last fragment waits alone.
        assert_eq!(offer(&mut reassembler, &datagrams[0][1], now), None);
        assert_eq!(stats.udp_reassembled(), 1);
    }

    #[test]
    fn held_bytes_stay_within_the_limit() {
        let (mut reassembler, stats) = fresh();
        let start = Instant::now();
        // Five datagrams of 60000 bytes, each missing its last fragment:
        // only four fit, so the first one makes room.
        let datagrams: Vec<Vec<Vec<u8>>> = (1..=5)
            .map(|id| fragments4(&udp4(&[5; 60_000], id), 1480))
            .collect();
        for (index, fragments) in datagrams.iter().enumerate() {
            let now = start + Duration::from_millis(index as u64);
            for fragment in &fragments[..fragments.len() - 1] {
                assert_eq!(offer(&mut reassembler, fragment, now), None);
                assert!(reassembler.bytes <= MAX_BYTES);
            }
        }
        assert_eq!(reassembler.datagrams.len(), 4);
        let held = datagrams[0].len() - 1;
        assert_eq!(stats.ip_fragments_dropped(), held as u64);
        let now = start + Duration::from_secs(1);
        let last = &datagrams[4][datagrams[4].len() - 1];
        assert_eq!(
            offer(&mut reassembler, last, now),
            Some(udp4(&[5; 60_000], 5))
        );
        let last = &datagrams[0][datagrams[0].len() - 1];
        assert_eq!(offer(&mut reassembler, last, now), None);
    }

    #[test]
    fn tiny_fragments_meet_the_limit_too() {
        let (mut reassembler, stats) = fresh();
        let now = Instant::now();
        // 5001 fragments of 8 bytes: with what each one costs to hold, the
        // datagram cannot fit alone. It is dropped whenever it reaches the
        // limit and never comes out.
        let tiny = fragments4(&udp4(&[6; 40_000], 77), 8);
        for fragment in &tiny {
            assert_eq!(offer(&mut reassembler, fragment, now), None);
            assert!(reassembler.bytes <= MAX_BYTES);
        }
        assert_eq!(stats.udp_reassembled(), 0);
        let held = MAX_BYTES / (8 + FRAGMENT_OVERHEAD);
        assert_eq!(stats.ip_fragments_dropped(), held as u64 + 1);
    }
}
