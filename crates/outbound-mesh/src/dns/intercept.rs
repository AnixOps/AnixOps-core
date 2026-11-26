//! The network's resolver address on the virtual interface (spec §15.9.2
//! item 8): DNS queries a full node's system sends to port 53 of
//! `dns.resolver_address` are answered here from the name list, over UDP
//! and TCP, and never leave the machine. The address belongs to no member,
//! so nothing else sent to it is forwarded either.
//!
//! TCP is a minimal responder for one query per connection, which is what
//! resolvers send after a truncated UDP answer: it takes the query (also in
//! several segments), sends the answer and a FIN, and forgets the
//! connection once the asker closes its side or after
//! [`FLOW_IDLE`]. The interface is local, so nothing is retransmitted on a
//! timer; an asker that sends its query again gets the answer again.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::message::Transport;
use super::Names;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP_HEADER: usize = 20;
const HOP_LIMIT: u8 = 64;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// Most TCP connections to the resolver at once; a new one replaces the
/// one idle longest.
pub const MAX_TCP_FLOWS: usize = 64;
/// A TCP connection with nothing heard for this long is forgotten.
pub const FLOW_IDLE: Duration = Duration::from_secs(30);
/// Longest TCP query, with its two-byte length; DNS queries are far
/// shorter. A longer one resets the connection.
const MAX_TCP_QUERY: usize = 2 + 4096;
/// The receive window advertised.
const WINDOW: u16 = 8192;
/// Segment size when the asker gives none (RFC 9293 §3.7.1).
const DEFAULT_MSS_V4: usize = 536;
const DEFAULT_MSS_V6: usize = 1220;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Flow {
    client: IpAddr,
    port: u16,
}

struct TcpFlow {
    last: Instant,
    isn: u32,
    /// The next sequence number expected from the asker.
    rcv_nxt: u32,
    /// The segment size towards the asker.
    mss: usize,
    /// The query so far, with its length prefix.
    buffer: Vec<u8>,
    /// The answer's segments once sent: (sequence, flags, payload).
    sent: Option<Vec<(u32, u8, Vec<u8>)>>,
}

impl TcpFlow {
    /// The sequence number of this side's next byte.
    fn snd_nxt(&self) -> u32 {
        match &self.sent {
            None => self.isn.wrapping_add(1),
            Some(segments) => {
                segments
                    .last()
                    .map_or(self.isn.wrapping_add(1), |(seq, flags, payload)| {
                        seq.wrapping_add(payload.len() as u32)
                            .wrapping_add(u32::from(flags & FIN != 0))
                    })
            }
        }
    }
}

/// `a` comes before `b` in sequence space.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Answers the resolver address of one network.
pub struct Interceptor {
    flows: BTreeMap<Flow, TcpFlow>,
    /// Mixed into initial sequence numbers.
    seed: u64,
    counter: u64,
    mtu: u16,
}

/// One parsed IP packet.
struct Datagram<'a> {
    source: IpAddr,
    destination: IpAddr,
    /// The IPv4 protocol, or the IPv6 next header: an extension header is
    /// neither UDP nor TCP, so such packets are dropped.
    protocol: u8,
    /// An IPv4 fragment; never answered.
    fragment: bool,
    payload: &'a [u8],
}

/// Reads the fixed header; `None` for anything malformed.
fn parse(packet: &[u8]) -> Option<Datagram<'_>> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            let header = usize::from(first & 0x0f) * 4;
            if header < IPV4_HEADER || packet.len() < header {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < header || total > packet.len() {
                return None;
            }
            // More fragments, or an offset.
            let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
            Some(Datagram {
                source: IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                destination: IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                protocol: packet[9],
                fragment,
                payload: &packet[header..total],
            })
        }
        6 => {
            if packet.len() < IPV6_HEADER {
                return None;
            }
            let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if IPV6_HEADER + length > packet.len() {
                return None;
            }
            let mut source = [0u8; 16];
            source.copy_from_slice(&packet[8..24]);
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&packet[24..40]);
            Some(Datagram {
                source: IpAddr::V6(Ipv6Addr::from(source)),
                destination: IpAddr::V6(Ipv6Addr::from(destination)),
                protocol: packet[6],
                fragment: false,
                payload: &packet[IPV6_HEADER..IPV6_HEADER + length],
            })
        }
        _ => None,
    }
}

/// The Internet checksum of the pseudo header and `segment`.
fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut data = Vec::with_capacity(40 + segment.len() + 1);
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            data.extend_from_slice(&source.octets());
            data.extend_from_slice(&destination.octets());
            data.extend_from_slice(&[0, protocol]);
            data.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (source, destination) => {
            data.extend_from_slice(&v6_octets(source));
            data.extend_from_slice(&v6_octets(destination));
            data.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            data.extend_from_slice(&[0, 0, 0, protocol]);
        }
    }
    data.extend_from_slice(segment);
    checksum(&data)
}

fn v6_octets(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in data.chunks(2) {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IP packet around `segment`, whose checksum field (at
/// `checksum_at`) is filled in here.
fn ip_packet(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    mut segment: Vec<u8>,
    checksum_at: usize,
) -> Vec<u8> {
    let mut sum = transport_checksum(source, destination, protocol, &segment);
    if protocol == PROTO_UDP && sum == 0 {
        sum = 0xffff;
    }
    segment[checksum_at..checksum_at + 2].copy_from_slice(&sum.to_be_bytes());
    let mut out;
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            out = Vec::with_capacity(IPV4_HEADER + segment.len());
            out.extend_from_slice(&[0x45, 0]);
            out.extend_from_slice(&((IPV4_HEADER + segment.len()) as u16).to_be_bytes());
            // ID 0, don't fragment.
            out.extend_from_slice(&[0, 0, 0x40, 0, HOP_LIMIT, protocol, 0, 0]);
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
            let header = checksum(&out);
            out[10..12].copy_from_slice(&header.to_be_bytes());
        }
        (source, destination) => {
            out = Vec::with_capacity(IPV6_HEADER + segment.len());
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            out.extend_from_slice(&[protocol, HOP_LIMIT]);
            out.extend_from_slice(&v6_octets(source));
            out.extend_from_slice(&v6_octets(destination));
        }
    }
    out.extend_from_slice(&segment);
    out
}

/// One TCP segment's fields.
struct Segment<'a> {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
    payload: &'a [u8],
}

fn parse_tcp(segment: &[u8]) -> Option<Segment<'_>> {
    if segment.len() < TCP_HEADER {
        return None;
    }
    let offset = usize::from(segment[12] >> 4) * 4;
    if offset < TCP_HEADER || offset > segment.len() {
        return None;
    }
    let mut mss = None;
    let mut options = &segment[TCP_HEADER..offset];
    while let Some(&kind) = options.first() {
        match kind {
            0 => break,
            1 => options = &options[1..],
            _ => {
                let len = usize::from(*options.get(1)?);
                if len < 2 || len > options.len() {
                    return None;
                }
                if kind == 2 && len == 4 {
                    mss = Some(u16::from_be_bytes([options[2], options[3]]));
                }
                options = &options[len..];
            }
        }
    }
    let word = |at: usize| {
        u32::from_be_bytes([
            segment[at],
            segment[at + 1],
            segment[at + 2],
            segment[at + 3],
        ])
    };
    Some(Segment {
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        seq: word(4),
        ack: word(8),
        flags: segment[13],
        mss,
        payload: &segment[offset..],
    })
}

impl Interceptor {
    /// `seed` comes from the node's random source; `mtu` is the virtual
    /// interface's.
    pub fn new(seed: u64, mtu: u16) -> Self {
        Self {
            flows: BTreeMap::new(),
            seed,
            counter: 0,
            mtu,
        }
    }

    /// Open TCP connections, for tests and the status.
    pub fn tcp_flows(&self) -> usize {
        self.flows.len()
    }

    /// Takes `packet` from the virtual interface when it is addressed to
    /// the resolver address of `names`, and gives the packets to write
    /// back (possibly none). `None` when the packet is not for it, so it
    /// goes on into the mesh as usual.
    pub fn handle(&mut self, packet: &[u8], names: &Names, now: Instant) -> Option<Vec<Vec<u8>>> {
        let resolver = names.resolver_address()?;
        let datagram = parse(packet)?;
        if datagram.destination != resolver {
            return None;
        }
        if datagram.fragment {
            return Some(Vec::new());
        }
        let replies = match datagram.protocol {
            PROTO_UDP => udp(&datagram, names).into_iter().collect(),
            PROTO_TCP => self.tcp(&datagram, names, now),
            _ => Vec::new(),
        };
        Some(replies)
    }

    fn next_isn(&mut self) -> u32 {
        // splitmix64 of the seed and a counter.
        self.counter = self.counter.wrapping_add(1);
        let mut z = self
            .seed
            .wrapping_add(self.counter.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) as u32
    }

    /// This side's segment size: the interface MTU less the headers.
    fn own_mss(&self, client: IpAddr) -> usize {
        let ip = if client.is_ipv4() {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        };
        usize::from(self.mtu).saturating_sub(ip + TCP_HEADER).max(1)
    }

    fn tcp(&mut self, datagram: &Datagram<'_>, names: &Names, now: Instant) -> Vec<Vec<u8>> {
        let Some(segment) = parse_tcp(datagram.payload) else {
            return Vec::new();
        };
        let (client, resolver) = (datagram.source, datagram.destination);
        let flow = Flow {
            client,
            port: segment.source_port,
        };
        let send = |seq: u32, ack: u32, flags: u8, mss: Option<u16>, payload: &[u8]| {
            tcp_packet(
                resolver,
                client,
                segment.source_port,
                seq,
                ack,
                flags,
                mss,
                payload,
            )
        };
        if segment.flags & RST != 0 {
            self.flows.remove(&flow);
            return Vec::new();
        }
        let reset = || {
            let length = segment.payload.len() as u32
                + u32::from(segment.flags & SYN != 0)
                + u32::from(segment.flags & FIN != 0);
            if segment.flags & ACK != 0 {
                send(segment.ack, 0, RST, None, &[])
            } else {
                send(0, segment.seq.wrapping_add(length), RST | ACK, None, &[])
            }
        };
        if segment.destination_port != DNS_PORT {
            return vec![reset()];
        }
        self.flows
            .retain(|_, open| now.saturating_duration_since(open.last) < FLOW_IDLE);

        if segment.flags & SYN != 0 && segment.flags & ACK == 0 {
            let rcv_nxt = segment.seq.wrapping_add(1);
            let own_mss = self.own_mss(client);
            // A SYN sent again gets the same answer.
            let isn = match self.flows.get(&flow) {
                Some(open)
                    if open.rcv_nxt == rcv_nxt && open.sent.is_none() && open.buffer.is_empty() =>
                {
                    open.isn
                }
                _ => {
                    if !self.flows.contains_key(&flow) && self.flows.len() >= MAX_TCP_FLOWS {
                        let idle = self
                            .flows
                            .iter()
                            .min_by_key(|(_, open)| open.last)
                            .map(|(flow, _)| *flow);
                        if let Some(idle) = idle {
                            self.flows.remove(&idle);
                        }
                    }
                    self.next_isn()
                }
            };
            let default = if client.is_ipv4() {
                DEFAULT_MSS_V4
            } else {
                DEFAULT_MSS_V6
            };
            let asked = segment.mss.map_or(default, usize::from).max(1);
            self.flows.insert(
                flow,
                TcpFlow {
                    last: now,
                    isn,
                    rcv_nxt,
                    mss: asked.min(own_mss),
                    buffer: Vec::new(),
                    sent: None,
                },
            );
            let advertised = u16::try_from(own_mss).unwrap_or(u16::MAX);
            return vec![send(isn, rcv_nxt, SYN | ACK, Some(advertised), &[])];
        }
        if segment.flags & ACK == 0 {
            return Vec::new();
        }
        let Some(open) = self.flows.get_mut(&flow) else {
            // A bare acknowledgement of a forgotten connection, typically of
            // the FIN, needs nothing.
            if segment.payload.is_empty() && segment.flags & FIN == 0 {
                return Vec::new();
            }
            return vec![reset()];
        };
        // An acknowledgement of something never sent.
        let snd_nxt = open.snd_nxt();
        if seq_lt(snd_nxt, segment.ack) || seq_lt(segment.ack, open.isn.wrapping_add(1)) {
            return vec![reset()];
        }
        open.last = now;

        let mut replies = Vec::new();
        let mut advanced = false;
        if !segment.payload.is_empty() {
            if segment.seq == open.rcv_nxt && open.sent.is_none() {
                if open.buffer.len() + segment.payload.len() > MAX_TCP_QUERY {
                    self.flows.remove(&flow);
                    return vec![reset()];
                }
                open.buffer.extend_from_slice(segment.payload);
                open.rcv_nxt = open.rcv_nxt.wrapping_add(segment.payload.len() as u32);
                advanced = true;
            } else if seq_lt(segment.seq, open.rcv_nxt) {
                // The query again: the answer again.
                if let Some(sent) = &open.sent {
                    for (seq, flags, payload) in sent {
                        replies.push(send(*seq, open.rcv_nxt, *flags, None, payload));
                    }
                    return replies;
                }
                advanced = true;
            }
        }
        let mut fin = false;
        if segment.flags & FIN != 0
            && segment.seq.wrapping_add(segment.payload.len() as u32) == open.rcv_nxt
        {
            open.rcv_nxt = open.rcv_nxt.wrapping_add(1);
            fin = true;
            advanced = true;
        }

        if open.sent.is_none() && open.buffer.len() >= 2 {
            let length = usize::from(u16::from_be_bytes([open.buffer[0], open.buffer[1]]));
            if open.buffer.len() >= 2 + length {
                let Some(answer) =
                    names.answer_at_resolver(&open.buffer[2..2 + length], Transport::Tcp)
                else {
                    self.flows.remove(&flow);
                    return vec![reset()];
                };
                let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&answer);
                let mut segments = Vec::new();
                let mut seq = open.isn.wrapping_add(1);
                let chunks: Vec<&[u8]> = framed.chunks(open.mss).collect();
                for (i, chunk) in chunks.iter().enumerate() {
                    let last = i + 1 == chunks.len();
                    let flags = ACK | PSH | if last { FIN } else { 0 };
                    segments.push((seq, flags, chunk.to_vec()));
                    seq = seq.wrapping_add(chunk.len() as u32);
                }
                for (seq, flags, payload) in &segments {
                    replies.push(send(*seq, open.rcv_nxt, *flags, None, payload));
                }
                open.sent = Some(segments);
                advanced = false;
            }
        }
        if advanced {
            replies.push(send(open.snd_nxt(), open.rcv_nxt, ACK, None, &[]));
        }
        if fin {
            // The asker closed its side: after the answer, or before a
            // whole query, when there is nothing to answer.
            self.flows.remove(&flow);
        }
        replies
    }
}

/// The answer to a UDP query to port 53; nothing for other ports.
fn udp(datagram: &Datagram<'_>, names: &Names) -> Option<Vec<u8>> {
    let segment = datagram.payload;
    if segment.len() < UDP_HEADER {
        return None;
    }
    let source_port = u16::from_be_bytes([segment[0], segment[1]]);
    let destination_port = u16::from_be_bytes([segment[2], segment[3]]);
    let length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
    if destination_port != DNS_PORT || length < UDP_HEADER || length > segment.len() {
        return None;
    }
    let answer = names.answer_at_resolver(&segment[UDP_HEADER..length], Transport::Udp)?;
    let mut out = Vec::with_capacity(UDP_HEADER + answer.len());
    out.extend_from_slice(&DNS_PORT.to_be_bytes());
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&((UDP_HEADER + answer.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&answer);
    Some(ip_packet(
        datagram.destination,
        datagram.source,
        PROTO_UDP,
        out,
        6,
    ))
}

/// One TCP segment from the resolver address, as an IP packet.
#[allow(clippy::too_many_arguments)]
fn tcp_packet(
    resolver: IpAddr,
    client: IpAddr,
    client_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let options = if mss.is_some() { 4 } else { 0 };
    let mut out = Vec::with_capacity(TCP_HEADER + options + payload.len());
    out.extend_from_slice(&DNS_PORT.to_be_bytes());
    out.extend_from_slice(&client_port.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.push((((TCP_HEADER + options) / 4) as u8) << 4);
    out.push(flags);
    out.extend_from_slice(&WINDOW.to_be_bytes());
    // Checksum, urgent pointer.
    out.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(mss) = mss {
        out.extend_from_slice(&[2, 4]);
        out.extend_from_slice(&mss.to_be_bytes());
    }
    out.extend_from_slice(payload);
    ip_packet(resolver, client, PROTO_TCP, out, 16)
}

#[cfg(test)]
mod tests {
    use super::super::message::tests::{parse_answer, query};
    use super::super::message::{Rcode, TYPE_A};
    use super::super::{DnsConfig, NetworkView};
    use super::*;
    use crate::net::IpNet;
    use serde_json::json;

    const CLIENT_V4: &str = "10.150.0.5";
    const RESOLVER_V4: &str = "10.150.255.254";
    const CLIENT_V6: &str = "fd00:150::5";
    const RESOLVER_V6: &str = "fd00:150::53";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn names(resolver: &str) -> Names {
        let subnets = [
            IpNet::parse("10.150.0.0/16").unwrap(),
            IpNet::parse("fd00:150::/64").unwrap(),
        ];
        let config: DnsConfig = serde_json::from_value(json!({
            "enabled": true,
            "region": "cn",
            "names": [{ "name": "web.cn", "address": "10.150.0.7" }],
            "resolver_address": resolver,
        }))
        .unwrap();
        let settings = config.validate(&subnets).unwrap();
        let local = [ip(CLIENT_V4), ip(CLIENT_V6)];
        Names::build(
            &settings,
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[],
                local_addresses: &local,
                own_hostname: None,
                members: &[],
            },
        )
    }

    /// An IP packet from `source` to `destination` around `segment`, with
    /// its checksum filled in.
    fn packet(source: &str, destination: &str, protocol: u8, segment: Vec<u8>) -> Vec<u8> {
        let at = if protocol == PROTO_UDP { 6 } else { 16 };
        ip_packet(ip(source), ip(destination), protocol, segment, at)
    }

    fn udp_query(source: &str, destination: &str, port: u16, message: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&40000u16.to_be_bytes());
        segment.extend_from_slice(&port.to_be_bytes());
        segment.extend_from_slice(&((UDP_HEADER + message.len()) as u16).to_be_bytes());
        segment.extend_from_slice(&[0, 0]);
        segment.extend_from_slice(message);
        packet(source, destination, PROTO_UDP, segment)
    }

    fn tcp_from_client(
        source: &str,
        destination: &str,
        port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&40001u16.to_be_bytes());
        segment.extend_from_slice(&port.to_be_bytes());
        segment.extend_from_slice(&seq.to_be_bytes());
        segment.extend_from_slice(&ack.to_be_bytes());
        let syn = flags & SYN != 0;
        segment.push(if syn { 6 << 4 } else { 5 << 4 });
        segment.push(flags);
        segment.extend_from_slice(&65535u16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        if syn {
            // MSS 20, so the answer needs several segments.
            segment.extend_from_slice(&[2, 4, 0, 20]);
        }
        segment.extend_from_slice(payload);
        packet(source, destination, PROTO_TCP, segment)
    }

    /// Checks the IP and transport checksums of a reply and gives its
    /// transport segment.
    fn verified(reply: &[u8]) -> (Datagram<'_>, Vec<u8>) {
        let datagram = parse(reply).unwrap();
        if reply[0] >> 4 == 4 {
            assert_eq!(checksum(&reply[..IPV4_HEADER]), 0, "IPv4 header checksum");
            assert_eq!(reply[8], HOP_LIMIT);
        } else {
            assert_eq!(reply[7], HOP_LIMIT);
        }
        assert_eq!(
            transport_checksum(
                datagram.source,
                datagram.destination,
                datagram.protocol,
                datagram.payload
            ),
            0,
            "transport checksum"
        );
        let segment = datagram.payload.to_vec();
        (datagram, segment)
    }

    #[test]
    fn answers_udp_queries_over_ipv4_and_ipv6() {
        let now = Instant::now();
        for (client, resolver) in [(CLIENT_V4, RESOLVER_V4), (CLIENT_V6, RESOLVER_V6)] {
            let names = names(resolver);
            let mut interceptor = Interceptor::new(1, 1380);
            let question = query(77, "web.cn.mesh.internal", TYPE_A, None);
            let replies = interceptor
                .handle(&udp_query(client, resolver, 53, &question), &names, now)
                .unwrap();
            assert_eq!(replies.len(), 1);
            let (datagram, segment) = verified(&replies[0]);
            assert_eq!(
                (datagram.source, datagram.destination),
                (ip(resolver), ip(client))
            );
            assert_eq!(datagram.protocol, PROTO_UDP);
            assert_eq!(u16::from_be_bytes([segment[0], segment[1]]), 53);
            assert_eq!(u16::from_be_bytes([segment[2], segment[3]]), 40000);
            assert_eq!(
                usize::from(u16::from_be_bytes([segment[4], segment[5]])),
                segment.len()
            );
            let answer = parse_answer(&segment[UDP_HEADER..]);
            assert_eq!(answer.id, 77);
            assert_eq!(answer.records, vec![(TYPE_A, 5, vec![10, 150, 0, 7])]);

            // Other names are refused, so the system moves to its next
            // server; nothing is forwarded.
            let other = query(78, "example.com", TYPE_A, None);
            let replies = interceptor
                .handle(&udp_query(client, resolver, 53, &other), &names, now)
                .unwrap();
            let (_, segment) = verified(&replies[0]);
            assert_eq!(
                parse_answer(&segment[UDP_HEADER..]).rcode,
                Rcode::Refused as u8
            );
        }
    }

    #[test]
    fn leaves_other_packets_alone_and_drops_the_rest() {
        let names = names(RESOLVER_V4);
        let now = Instant::now();
        let mut interceptor = Interceptor::new(1, 1380);
        let question = query(1, "web.cn.mesh.internal", TYPE_A, None);
        // Not addressed to the resolver: into the mesh as usual.
        assert_eq!(
            interceptor.handle(
                &udp_query(CLIENT_V4, "10.150.0.7", 53, &question),
                &names,
                now
            ),
            None
        );
        assert_eq!(interceptor.handle(&[0x45, 0, 0], &names, now), None);
        // To the resolver, other port: dropped.
        assert_eq!(
            interceptor.handle(
                &udp_query(CLIENT_V4, RESOLVER_V4, 54, &question),
                &names,
                now
            ),
            Some(Vec::new())
        );
        // A fragment: dropped.
        let mut fragment = udp_query(CLIENT_V4, RESOLVER_V4, 53, &question);
        fragment[6] |= 0x20;
        assert_eq!(interceptor.handle(&fragment, &names, now), Some(Vec::new()));
        // A response sent to the resolver: dropped, not answered.
        let mut response = question.clone();
        response[2] |= 0x80;
        assert_eq!(
            interceptor.handle(
                &udp_query(CLIENT_V4, RESOLVER_V4, 53, &response),
                &names,
                now
            ),
            Some(Vec::new())
        );
        // Names off, or no resolver address: nothing is intercepted.
        let config: DnsConfig = serde_json::from_value(json!({ "enabled": true })).unwrap();
        let subnets = [IpNet::parse("10.150.0.0/16").unwrap()];
        let none = Names::build(
            &config.validate(&subnets).unwrap(),
            &NetworkView {
                virtual_subnets: &subnets,
                host_groups: &[],
                local_addresses: &[ip(CLIENT_V4)],
                own_hostname: None,
                members: &[],
            },
        );
        assert_eq!(
            interceptor.handle(
                &udp_query(CLIENT_V4, RESOLVER_V4, 53, &question),
                &none,
                now
            ),
            None
        );
    }

    /// Reads the TCP fields of a reply.
    fn tcp_reply(reply: &[u8]) -> (u32, u32, u8, Option<u16>, Vec<u8>) {
        let (datagram, segment) = verified(reply);
        assert_eq!(datagram.protocol, PROTO_TCP);
        let parsed = parse_tcp(&segment).unwrap();
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 40001);
        (
            parsed.seq,
            parsed.ack,
            parsed.flags,
            parsed.mss,
            parsed.payload.to_vec(),
        )
    }

    #[test]
    fn answers_a_tcp_query_in_pieces_and_closes() {
        let names = names(RESOLVER_V4);
        let now = Instant::now();
        let mut interceptor = Interceptor::new(42, 1380);
        let send =
            |interceptor: &mut Interceptor, seq: u32, ack: u32, flags: u8, payload: &[u8]| {
                interceptor
                    .handle(
                        &tcp_from_client(CLIENT_V4, RESOLVER_V4, 53, seq, ack, flags, payload),
                        &names,
                        now,
                    )
                    .unwrap()
            };
        let replies = send(&mut interceptor, 1000, 0, SYN, &[]);
        let (isn, ack, flags, mss, _) = tcp_reply(&replies[0]);
        assert_eq!((ack, flags), (1001, SYN | ACK));
        assert_eq!(mss, Some(1380 - 40));
        // A SYN sent again gets the same answer.
        let again = send(&mut interceptor, 1000, 0, SYN, &[]);
        assert_eq!(tcp_reply(&again[0]).0, isn);
        assert!(send(&mut interceptor, 1001, isn.wrapping_add(1), ACK, &[]).is_empty());

        // The query with its length prefix, in two segments.
        let question = query(9, "web.cn.mesh.internal", TYPE_A, None);
        let mut framed = (question.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&question);
        let (first, second) = framed.split_at(5);
        let replies = send(&mut interceptor, 1001, isn.wrapping_add(1), ACK, first);
        let (seq, ack, flags, _, payload) = tcp_reply(&replies[0]);
        assert_eq!(
            (seq, ack, flags, payload.len()),
            (isn.wrapping_add(1), 1006, ACK, 0)
        );
        let replies = send(
            &mut interceptor,
            1006,
            isn.wrapping_add(1),
            ACK | PSH,
            second,
        );
        assert!(replies.len() > 1, "the asker's MSS of 20 splits the answer");
        let mut stream = Vec::new();
        let mut next = isn.wrapping_add(1);
        for (i, reply) in replies.iter().enumerate() {
            let (seq, ack, flags, _, payload) = tcp_reply(reply);
            assert_eq!(seq, next);
            assert_eq!(ack, 1001 + framed.len() as u32);
            assert!(payload.len() <= 20);
            let last = i + 1 == replies.len();
            assert_eq!(flags, ACK | PSH | if last { FIN } else { 0 });
            next = seq
                .wrapping_add(payload.len() as u32)
                .wrapping_add(u32::from(last));
            stream.extend_from_slice(&payload);
        }
        let length = usize::from(u16::from_be_bytes([stream[0], stream[1]]));
        assert_eq!(length, stream.len() - 2);
        let answer = parse_answer(&stream[2..]);
        assert_eq!(answer.id, 9);
        assert_eq!(answer.records, vec![(TYPE_A, 5, vec![10, 150, 0, 7])]);

        // The query again (our answer was lost): the answer again.
        let resent = send(&mut interceptor, 1001, isn.wrapping_add(1), ACK, &framed);
        assert_eq!(resent, replies);

        // The asker acknowledges and closes: acknowledged, forgotten.
        let end = 1001 + framed.len() as u32;
        assert!(send(&mut interceptor, end, next, ACK, &[]).is_empty());
        assert_eq!(interceptor.tcp_flows(), 1);
        let replies = send(&mut interceptor, end, next, ACK | FIN, &[]);
        let (seq, ack, flags, _, _) = tcp_reply(&replies[0]);
        assert_eq!((seq, ack, flags), (next, end + 1, ACK));
        assert_eq!(interceptor.tcp_flows(), 0);
        // A late bare acknowledgement needs nothing; data is reset.
        assert!(send(&mut interceptor, end + 1, next, ACK, &[]).is_empty());
        let reset = send(&mut interceptor, end + 1, next, ACK, b"xx");
        let (seq, _, flags, _, _) = tcp_reply(&reset[0]);
        assert_eq!((seq, flags), (next, RST));
    }

    #[test]
    fn resets_what_it_does_not_serve() {
        let names = names(RESOLVER_V6);
        let now = Instant::now();
        let mut interceptor = Interceptor::new(7, 1380);
        // Another port: reset.
        let replies = interceptor
            .handle(
                &tcp_from_client(CLIENT_V6, RESOLVER_V6, 80, 5, 0, SYN, &[]),
                &names,
                now,
            )
            .unwrap();
        let (seq, ack, flags, _, _) = tcp_reply(&replies[0]);
        assert_eq!((seq, ack, flags), (0, 6, RST | ACK));
        // An acknowledgement of something never sent: reset.
        let syn = interceptor
            .handle(
                &tcp_from_client(CLIENT_V6, RESOLVER_V6, 53, 5, 0, SYN, &[]),
                &names,
                now,
            )
            .unwrap();
        let (isn, _, _, mss, _) = tcp_reply(&syn[0]);
        assert_eq!(mss, Some(1380 - 60));
        let bad = interceptor
            .handle(
                &tcp_from_client(
                    CLIENT_V6,
                    RESOLVER_V6,
                    53,
                    6,
                    isn.wrapping_add(50),
                    ACK,
                    &[],
                ),
                &names,
                now,
            )
            .unwrap();
        assert_eq!(tcp_reply(&bad[0]).2, RST);
        // A query that is not DNS at all: reset, forgotten.
        let junk = interceptor
            .handle(
                &tcp_from_client(
                    CLIENT_V6,
                    RESOLVER_V6,
                    53,
                    6,
                    isn.wrapping_add(1),
                    ACK,
                    &[0, 3, 1, 2, 3],
                ),
                &names,
                now,
            )
            .unwrap();
        assert_eq!(tcp_reply(&junk[0]).2, RST);
        assert_eq!(interceptor.tcp_flows(), 0);
        // The asker's reset forgets the connection.
        interceptor
            .handle(
                &tcp_from_client(CLIENT_V6, RESOLVER_V6, 53, 5, 0, SYN, &[]),
                &names,
                now,
            )
            .unwrap();
        assert_eq!(interceptor.tcp_flows(), 1);
        let none = interceptor
            .handle(
                &tcp_from_client(CLIENT_V6, RESOLVER_V6, 53, 6, 0, RST, &[]),
                &names,
                now,
            )
            .unwrap();
        assert!(none.is_empty());
        assert_eq!(interceptor.tcp_flows(), 0);
    }

    #[test]
    fn bounds_and_expires_connections() {
        let names = names(RESOLVER_V4);
        let start = Instant::now();
        let mut interceptor = Interceptor::new(3, 1380);
        for port in 0..(MAX_TCP_FLOWS as u16 + 10) {
            let mut syn = tcp_from_client(CLIENT_V4, RESOLVER_V4, 53, 1, 0, SYN, &[]);
            // Another source port for each.
            syn[IPV4_HEADER..IPV4_HEADER + 2].copy_from_slice(&(1000 + port).to_be_bytes());
            let fixed = {
                let mut segment = syn[IPV4_HEADER..].to_vec();
                segment[16] = 0;
                segment[17] = 0;
                packet(CLIENT_V4, RESOLVER_V4, PROTO_TCP, segment)
            };
            let at = start + Duration::from_millis(u64::from(port));
            interceptor.handle(&fixed, &names, at).unwrap();
        }
        assert_eq!(interceptor.tcp_flows(), MAX_TCP_FLOWS);
        let later = start + FLOW_IDLE + Duration::from_secs(1);
        let syn = tcp_from_client(CLIENT_V4, RESOLVER_V4, 53, 1, 0, SYN, &[]);
        interceptor.handle(&syn, &names, later).unwrap();
        assert_eq!(interceptor.tcp_flows(), 1);
    }
}
