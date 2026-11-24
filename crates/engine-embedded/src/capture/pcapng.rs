//! A minimal pcapng writer: one raw-IP interface, synthetic IPv4/IPv6
//! TCP and UDP packets, and a name resolution block.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{destination_port, http_text, Captured, Direction, Network};

/// `LINKTYPE_RAW`: packets start with the IP header.
const LINKTYPE_RAW: u16 = 101;
/// Largest TCP or UDP payload per synthetic packet.
const SEGMENT: usize = 16 * 1024;
const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

pub(super) struct File {
    packets: Vec<u8>,
}

impl File {
    pub(super) fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    /// One enhanced packet block, with an optional comment.
    fn packet(&mut self, at_ms: u64, packet: &[u8], comment: Option<&str>) {
        let micros = at_ms.saturating_mul(1000);
        let mut options = Vec::new();
        if let Some(comment) = comment {
            option(&mut options, 1, comment.as_bytes());
            option(&mut options, 0, &[]);
        }
        let mut body = Vec::with_capacity(20 + packet.len() + 3 + options.len());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(micros as u32).to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(packet);
        pad(&mut body);
        body.extend_from_slice(&options);
        block(&mut self.packets, 6, &body);
    }

    /// The whole file: section header, interface, names, packets.
    pub(super) fn finish(self, names: &[(IpAddr, String)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.packets.len() + 256);
        let mut section = Vec::new();
        section.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        section.extend_from_slice(&1u16.to_le_bytes());
        section.extend_from_slice(&0u16.to_le_bytes());
        section.extend_from_slice(&(-1i64).to_le_bytes());
        let mut options = Vec::new();
        option(&mut options, 4, b"AnixOps Net");
        option(&mut options, 0, &[]);
        section.extend_from_slice(&options);
        block(&mut out, 0x0A0D_0D0A, &section);

        let mut interface = Vec::new();
        interface.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
        interface.extend_from_slice(&0u16.to_le_bytes());
        interface.extend_from_slice(&0u32.to_le_bytes());
        let mut options = Vec::new();
        option(&mut options, 2, b"anixops-tunnel");
        option(&mut options, 0, &[]);
        interface.extend_from_slice(&options);
        block(&mut out, 1, &interface);

        if !names.is_empty() {
            let mut records = Vec::new();
            for (address, name) in names {
                let mut value = match address {
                    IpAddr::V4(v4) => v4.octets().to_vec(),
                    IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                value.extend_from_slice(name.as_bytes());
                value.push(0);
                let kind = if address.is_ipv4() { 1 } else { 2 };
                option(&mut records, kind, &value);
            }
            option(&mut records, 0, &[]);
            block(&mut out, 4, &records);
        }
        out.extend_from_slice(&self.packets);
        out
    }
}

/// A block: type, total length, body, total length.
fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

/// An option (or name record): code, length, value padded to 32 bits.
fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    pad(out);
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// One connection as a synthetic flow between a fixed client address
/// and its server.
pub(super) struct Flow {
    id: u64,
    network: Network,
    client: SocketAddr,
    pub(super) server: SocketAddr,
    client_seq: u32,
    server_seq: u32,
}

impl Flow {
    pub(super) fn new(id: u64, captured: &Captured) -> Self {
        let port = destination_port(&captured.destination);
        let server = captured
            .destination
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| {
                // 198.18.0.0/15, one address per connection.
                let low = (id & 0x1_ffff) as u32;
                let address = Ipv4Addr::from(0xC612_0000 | low);
                SocketAddr::new(IpAddr::V4(address), port)
            });
        let client_ip = if server.is_ipv4() {
            IpAddr::V4(CLIENT_V4)
        } else {
            IpAddr::V6(CLIENT_V6)
        };
        let client_port = 10_000 + (id % 50_000) as u16;
        Self {
            id,
            network: captured.network,
            client: SocketAddr::new(client_ip, client_port),
            server,
            client_seq: 1_000,
            server_seq: 50_000,
        }
    }

    pub(super) fn write(mut self, file: &mut File, captured: &Captured, redact: bool) {
        let comment = format!(
            "anixops connection {}: {}{}",
            self.id,
            captured
                .host
                .as_deref()
                .map(|host| format!("{host} "))
                .unwrap_or_default(),
            captured.destination,
        );
        let pieces: Vec<(Direction, u64, Vec<u8>)> = if captured.decrypted {
            // Exchanges with no response yet go last, so each response
            // pairs with its own request when the stream is read in
            // order.
            let (answered, unanswered): (Vec<_>, Vec<_>) = captured
                .http
                .iter()
                .partition(|exchange| exchange.status.is_some());
            answered
                .into_iter()
                .chain(unanswered)
                .flat_map(|exchange| {
                    let exchange = super::redacted(exchange, redact);
                    let (up, down) = http_text(&exchange);
                    let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
                    [
                        (Direction::Up, exchange.started_at_ms, up),
                        (Direction::Down, ended, down),
                    ]
                })
                .filter(|(_, _, data)| !data.is_empty())
                .collect()
        } else {
            // Joined so that masking sees each TCP run whole, not the
            // pieces it is kept in.
            captured
                .joined_chunks()
                .into_iter()
                .map(|(direction, at_ms, data)| {
                    let data = if redact {
                        super::redact::http1_text(&data).into_owned()
                    } else {
                        data
                    };
                    (direction, at_ms, data)
                })
                .collect()
        };
        match self.network {
            Network::Tcp => {
                let start = captured.started_at_ms;
                self.tcp(file, start, TCP_SYN, Direction::Up, &[], Some(&comment));
                self.tcp(file, start, TCP_SYN | TCP_ACK, Direction::Down, &[], None);
                self.tcp(file, start, TCP_ACK, Direction::Up, &[], None);
                for (direction, at_ms, data) in pieces {
                    for segment in data.chunks(SEGMENT) {
                        self.tcp(file, at_ms, TCP_PSH | TCP_ACK, direction, segment, None);
                    }
                }
                if let Some(end) = captured.ended_at_ms {
                    self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Up, &[], None);
                    self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Down, &[], None);
                    self.tcp(file, end, TCP_ACK, Direction::Up, &[], None);
                }
            }
            Network::Udp => {
                let mut first = Some(comment.as_str());
                for (direction, at_ms, data) in pieces {
                    for datagram in data.chunks(SEGMENT) {
                        let packet = self.ip(direction, 17, &udp(self.ends(direction), datagram));
                        file.packet(at_ms, &packet, first.take());
                    }
                }
            }
        }
    }

    fn ends(&self, direction: Direction) -> (SocketAddr, SocketAddr) {
        match direction {
            Direction::Up => (self.client, self.server),
            Direction::Down => (self.server, self.client),
        }
    }

    fn tcp(
        &mut self,
        file: &mut File,
        at_ms: u64,
        flags: u8,
        direction: Direction,
        payload: &[u8],
        comment: Option<&str>,
    ) {
        let (seq, ack) = match direction {
            Direction::Up => (self.client_seq, self.server_seq),
            Direction::Down => (self.server_seq, self.client_seq),
        };
        let ack = if flags & TCP_ACK != 0 { ack } else { 0 };
        let (source, destination) = self.ends(direction);
        let mut segment = Vec::with_capacity(20 + payload.len());
        segment.extend_from_slice(&source.port().to_be_bytes());
        segment.extend_from_slice(&destination.port().to_be_bytes());
        segment.extend_from_slice(&seq.to_be_bytes());
        segment.extend_from_slice(&ack.to_be_bytes());
        segment.push(5 << 4);
        segment.push(flags);
        segment.extend_from_slice(&65_535u16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(payload);
        let checksum = transport_checksum(source.ip(), destination.ip(), 6, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
        let advance = payload.len() as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0);
        match direction {
            Direction::Up => self.client_seq = self.client_seq.wrapping_add(advance),
            Direction::Down => self.server_seq = self.server_seq.wrapping_add(advance),
        }
        let packet = self.ip(direction, 6, &segment);
        file.packet(at_ms, &packet, comment);
    }

    fn ip(&self, direction: Direction, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let (source, destination) = self.ends(direction);
        match (source.ip(), destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let total = (20 + payload.len()) as u16;
                let mut header = Vec::with_capacity(20 + payload.len());
                header.extend_from_slice(&[0x45, 0]);
                header.extend_from_slice(&total.to_be_bytes());
                header.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
                header.extend_from_slice(&source.octets());
                header.extend_from_slice(&destination.octets());
                let checksum = fold(sum(&header, 0));
                header[10..12].copy_from_slice(&checksum.to_be_bytes());
                header.extend_from_slice(payload);
                header
            }
            (source, destination) => {
                let mut header = Vec::with_capacity(40 + payload.len());
                header.extend_from_slice(&[0x60, 0, 0, 0]);
                header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                header.push(protocol);
                header.push(64);
                header.extend_from_slice(&v6(source).octets());
                header.extend_from_slice(&v6(destination).octets());
                header.extend_from_slice(payload);
                header
            }
        }
    }
}

fn v6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn udp((source, destination): (SocketAddr, SocketAddr), payload: &[u8]) -> Vec<u8> {
    let length = (8 + payload.len()) as u16;
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&source.port().to_be_bytes());
    datagram.extend_from_slice(&destination.port().to_be_bytes());
    datagram.extend_from_slice(&length.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    let checksum = match transport_checksum(source.ip(), destination.ip(), 17, &datagram) {
        0 => 0xffff,
        value => value,
    };
    datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
    datagram
}

/// The TCP/UDP checksum over the pseudo header and `segment`.
fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (source, destination) => {
            pseudo.extend_from_slice(&v6(source).octets());
            pseudo.extend_from_slice(&v6(destination).octets());
            pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
    }
    fold(sum(segment, sum(&pseudo, 0)))
}

fn sum(bytes: &[u8], mut acc: u32) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    for pair in pairs {
        acc = acc.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
    }
    if let [last] = rest {
        acc = acc.wrapping_add(u32::from(*last) << 8);
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_verify_to_zero() {
        let header = [
            0x45u8, 0, 0, 0x1c, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 7, 0, 1, 192, 0, 2, 1,
        ];
        let checksum = fold(sum(&header, 0));
        let mut filled = header;
        filled[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(fold(sum(&filled, 0)), 0);
    }
}
