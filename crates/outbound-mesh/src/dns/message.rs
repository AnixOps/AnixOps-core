//! The part of the DNS message format (RFC 1035 §4, RFC 6891 for EDNS)
//! the intranet name module needs: reading one question and writing an
//! answer to it. Nothing here sends a query anywhere.

use std::net::IpAddr;

/// Header length.
pub const HEADER_LEN: usize = 12;
/// Largest UDP answer without EDNS (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_LIMIT: usize = 512;
/// Largest UDP answer this module gives with EDNS: the size that avoids
/// fragmentation on common paths (DNS flag day 2020).
pub const EDNS_UDP_LIMIT: usize = 1232;
/// Largest message over TCP (two-byte length prefix).
pub const TCP_LIMIT: usize = 65_535;
/// Longest name in wire form (RFC 1035 §2.3.4).
const MAX_NAME_WIRE: usize = 255;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;

/// Response codes used here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

/// How the query arrived, which bounds the answer's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// One parsed query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// The recursion-desired bit, copied into the answer.
    pub rd: bool,
    pub opcode: u8,
    /// The question's labels, ASCII lower-cased, for matching.
    pub labels: Vec<Vec<u8>>,
    pub qtype: u16,
    pub qclass: u16,
    /// The question section as received (name, type and class), copied
    /// into the answer so the asker sees its own spelling.
    pub question: Vec<u8>,
    /// The EDNS version and the requestor's UDP payload size, when the
    /// query carries an OPT record.
    pub edns: Option<(u8, u16)>,
}

/// Why a message is not a query this module can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Too short for a header, or a response: nothing is answered.
    Ignore,
    /// A query that cannot be read past its header: FORMERR, or NOTIMP
    /// for another opcode.
    Bad(Rcode),
}

impl Query {
    pub fn parse(message: &[u8]) -> Result<Self, ParseError> {
        if message.len() < HEADER_LEN {
            return Err(ParseError::Ignore);
        }
        let flags = u16::from_be_bytes([message[2], message[3]]);
        if flags & 0x8000 != 0 {
            return Err(ParseError::Ignore);
        }
        let opcode = ((flags >> 11) & 0x0f) as u8;
        if opcode != 0 {
            return Err(ParseError::Bad(Rcode::NotImp));
        }
        let count = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
        let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
        if qd != 1 || an != 0 || ns != 0 {
            return Err(ParseError::Bad(Rcode::FormErr));
        }
        let bad = ParseError::Bad(Rcode::FormErr);
        let mut at = HEADER_LEN;
        let mut labels = Vec::new();
        let mut wire = 1;
        loop {
            let len = usize::from(*message.get(at).ok_or(bad)?);
            at += 1;
            if len == 0 {
                break;
            }
            // No compression in a question that has nothing before it.
            if len > 63 {
                return Err(bad);
            }
            wire += len + 1;
            if wire > MAX_NAME_WIRE {
                return Err(bad);
            }
            let label = message.get(at..at + len).ok_or(bad)?;
            labels.push(label.to_ascii_lowercase());
            at += len;
        }
        let fixed = message.get(at..at + 4).ok_or(bad)?;
        let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let question = message[HEADER_LEN..at + 4].to_vec();
        at += 4;
        let mut edns = None;
        for _ in 0..ar {
            let name_end = skip_name(message, at).ok_or(bad)?;
            let fixed = message.get(name_end..name_end + 10).ok_or(bad)?;
            let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
            let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
            let version = fixed[5];
            let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
            let end = name_end + 10 + rdlen;
            if end > message.len() {
                return Err(bad);
            }
            if rtype == TYPE_OPT {
                // One OPT record, owned by the root (RFC 6891 §6.1.1).
                if edns.is_some() || name_end != at + 1 {
                    return Err(bad);
                }
                edns = Some((version, rclass));
            }
            at = end;
        }
        Ok(Self {
            id: u16::from_be_bytes([message[0], message[1]]),
            rd: flags & 0x0100 != 0,
            opcode,
            labels,
            qtype,
            qclass,
            question,
            edns,
        })
    }

    /// The largest answer the asker takes over `transport`.
    pub fn limit(&self, transport: Transport) -> usize {
        match transport {
            Transport::Tcp => TCP_LIMIT,
            Transport::Udp => match self.edns {
                Some((_, size)) => usize::from(size).clamp(CLASSIC_UDP_LIMIT, EDNS_UDP_LIMIT),
                None => CLASSIC_UDP_LIMIT,
            },
        }
    }
}

/// The end of a name that may be compressed, without following pointers.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        match len {
            0 => return Some(at + 1),
            0xc0..=0xff => {
                message.get(at + 1)?;
                return Some(at + 2);
            }
            1..=63 => at += 1 + usize::from(len),
            _ => return None,
        }
    }
}

/// The header ID and recursion bit of a message too broken to parse
/// further, for a FORMERR or NOTIMP answer; `None` when it is not a query.
pub fn header_of(message: &[u8]) -> Option<(u16, bool, u8)> {
    if message.len() < HEADER_LEN || message[2] & 0x80 != 0 {
        return None;
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    Some((
        u16::from_be_bytes([message[0], message[1]]),
        flags & 0x0100 != 0,
        ((flags >> 11) & 0x0f) as u8,
    ))
}

/// The question name of a query [`Query::parse`] refused, lower-cased,
/// when the name itself can be read; `None` for a response or a message
/// without a readable question.
pub fn question_labels(message: &[u8]) -> Option<Vec<Vec<u8>>> {
    if message.len() < HEADER_LEN || message[2] & 0x80 != 0 {
        return None;
    }
    if u16::from_be_bytes([message[4], message[5]]) == 0 {
        return None;
    }
    let mut at = HEADER_LEN;
    let mut labels = Vec::new();
    let mut wire = 1;
    loop {
        let len = usize::from(*message.get(at)?);
        at += 1;
        if len == 0 {
            return Some(labels);
        }
        if len > 63 {
            return None;
        }
        wire += len + 1;
        if wire > MAX_NAME_WIRE {
            return None;
        }
        labels.push(message.get(at..at + len)?.to_ascii_lowercase());
        at += len;
    }
}

/// An answer with no question section, for a query that could not be read.
pub fn bare_answer(id: u16, rd: bool, opcode: u8, rcode: Rcode) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&id.to_be_bytes());
    let flags =
        0x8000 | (u16::from(opcode & 0x0f) << 11) | (u16::from(rd) << 8) | 0x0080 | rcode as u16;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

/// One answer record's data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Address(IpAddr),
    /// A PTR target, as labels.
    Pointer(Vec<Vec<u8>>),
}

impl Record {
    fn rtype(&self) -> u16 {
        match self {
            Record::Address(IpAddr::V4(_)) => TYPE_A,
            Record::Address(IpAddr::V6(_)) => TYPE_AAAA,
            Record::Pointer(_) => TYPE_PTR,
        }
    }

    fn rdata(&self) -> Vec<u8> {
        match self {
            Record::Address(IpAddr::V4(v4)) => v4.octets().to_vec(),
            Record::Address(IpAddr::V6(v6)) => v6.octets().to_vec(),
            Record::Pointer(labels) => {
                let mut out = Vec::new();
                for label in labels {
                    out.push(label.len() as u8);
                    out.extend_from_slice(label);
                }
                out.push(0);
                out
            }
        }
    }
}

/// Writes the answer to `query`: `rcode`, then `records` (all owned by the
/// question's name) while they fit in `limit` bytes, setting TC when one
/// does not or when `truncated` says some were left out already.
pub fn answer(
    query: &Query,
    rcode: Rcode,
    records: &[Record],
    ttl: u32,
    truncated: bool,
    limit: usize,
) -> Vec<u8> {
    // EDNS versions other than 0 get BADVERS (RFC 6891 §6.1.3): extended
    // rcode 1 in the OPT record, nothing else.
    let bad_version = matches!(query.edns, Some((version, _)) if version != 0);
    let opt_len = if query.edns.is_some() { 11 } else { 0 };
    let records = if bad_version { &[][..] } else { records };
    let rcode = if bad_version { Rcode::NoError } else { rcode };

    let mut body = Vec::new();
    let mut count: u16 = 0;
    let mut tc = truncated;
    let base = HEADER_LEN + query.question.len() + opt_len;
    for record in records {
        let rdata = record.rdata();
        // Owner: a pointer to the question's name at offset 12.
        let len = 2 + 10 + rdata.len();
        if base + body.len() + len > limit {
            tc = true;
            break;
        }
        body.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        body.extend_from_slice(&record.rtype().to_be_bytes());
        body.extend_from_slice(&CLASS_IN.to_be_bytes());
        body.extend_from_slice(&ttl.to_be_bytes());
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);
        count += 1;
    }

    let mut out = Vec::with_capacity(base + body.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR, AA, RD as asked, RA.
    let flags = 0x8000
        | 0x0400
        | if tc { 0x0200 } else { 0 }
        | (u16::from(query.rd) << 8)
        | 0x0080
        | rcode as u16;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(query.edns.is_some()).to_be_bytes());
    out.extend_from_slice(&query.question);
    out.extend_from_slice(&body);
    if query.edns.is_some() {
        // Root owner, OPT, our UDP size, extended rcode, version 0, no
        // flags, no options.
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&(EDNS_UDP_LIMIT as u16).to_be_bytes());
        out.push(u8::from(bad_version));
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A query for `name` of `qtype`, with an OPT record of `edns` size.
    pub(crate) fn query(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&u16::from(edns.is_some()).to_be_bytes());
        for label in name.split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        if let Some(size) = edns {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        out
    }

    /// What a test reads back from an answer.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Parsed {
        pub id: u16,
        pub rcode: u8,
        pub aa: bool,
        pub tc: bool,
        pub records: Vec<(u16, u32, Vec<u8>)>,
        pub opt: Option<(u16, u8)>,
    }

    pub(crate) fn parse_answer(message: &[u8]) -> Parsed {
        let flags = u16::from_be_bytes([message[2], message[3]]);
        assert_ne!(flags & 0x8000, 0, "QR");
        let count = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
        let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
        assert_eq!(ns, 0);
        let mut at = HEADER_LEN;
        for _ in 0..qd {
            at = skip_name(message, at).unwrap() + 4;
        }
        let mut records = Vec::new();
        for _ in 0..an {
            at = skip_name(message, at).unwrap();
            let rtype = u16::from_be_bytes([message[at], message[at + 1]]);
            let ttl = u32::from_be_bytes(message[at + 4..at + 8].try_into().unwrap());
            let len = usize::from(u16::from_be_bytes([message[at + 8], message[at + 9]]));
            records.push((rtype, ttl, message[at + 10..at + 10 + len].to_vec()));
            at += 10 + len;
        }
        let mut opt = None;
        for _ in 0..ar {
            at = skip_name(message, at).unwrap();
            let rtype = u16::from_be_bytes([message[at], message[at + 1]]);
            assert_eq!(rtype, TYPE_OPT);
            let size = u16::from_be_bytes([message[at + 2], message[at + 3]]);
            opt = Some((size, message[at + 4]));
            let len = usize::from(u16::from_be_bytes([message[at + 8], message[at + 9]]));
            at += 10 + len;
        }
        assert_eq!(at, message.len(), "no trailing bytes");
        Parsed {
            id: u16::from_be_bytes([message[0], message[1]]),
            rcode: (flags & 0x0f) as u8,
            aa: flags & 0x0400 != 0,
            tc: flags & 0x0200 != 0,
            records,
            opt,
        }
    }

    #[test]
    fn parses_a_query_and_keeps_its_spelling() {
        let message = query(7, "Web.CN.Mesh.Internal", TYPE_A, None);
        let parsed = Query::parse(&message).unwrap();
        assert_eq!(parsed.id, 7);
        assert!(parsed.rd);
        let labels: Vec<Vec<u8>> = ["web", "cn", "mesh", "internal"]
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect();
        assert_eq!(parsed.labels, labels);
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(parsed.edns, None);
        let reply = answer(
            &parsed,
            Rcode::NoError,
            &[Record::Address("10.0.0.1".parse().unwrap())],
            5,
            false,
            parsed.limit(Transport::Udp),
        );
        // The question is echoed byte for byte, upper case included.
        assert_eq!(&reply[HEADER_LEN..message.len()], &message[HEADER_LEN..]);
        let read = parse_answer(&reply);
        assert_eq!(read.id, 7);
        assert!(read.aa);
        assert_eq!(read.records, vec![(TYPE_A, 5, vec![10, 0, 0, 1])]);
    }

    #[test]
    fn refuses_malformed_queries() {
        assert_eq!(Query::parse(&[0; 5]), Err(ParseError::Ignore));
        let mut response = query(1, "a.internal", TYPE_A, None);
        response[2] |= 0x80;
        assert_eq!(Query::parse(&response), Err(ParseError::Ignore));
        let mut update = query(1, "a.internal", TYPE_A, None);
        update[2] |= 5 << 3;
        assert_eq!(Query::parse(&update), Err(ParseError::Bad(Rcode::NotImp)));
        let mut cut = query(1, "a.internal", TYPE_A, None);
        cut.truncate(cut.len() - 2);
        assert_eq!(Query::parse(&cut), Err(ParseError::Bad(Rcode::FormErr)));
        let mut two = query(1, "a.internal", TYPE_A, None);
        two[5] = 2;
        assert_eq!(Query::parse(&two), Err(ParseError::Bad(Rcode::FormErr)));
        // A compression pointer in the question.
        let mut pointer = query(1, "a.internal", TYPE_A, None);
        pointer[HEADER_LEN] = 0xc0;
        assert_eq!(Query::parse(&pointer), Err(ParseError::Bad(Rcode::FormErr)));
        // A name over 255 bytes.
        let long = vec!["a".repeat(63); 4].join(".");
        assert_eq!(
            Query::parse(&query(1, &long, TYPE_A, None)),
            Err(ParseError::Bad(Rcode::FormErr))
        );
        let reply = bare_answer(9, true, 5, Rcode::NotImp);
        assert_eq!(header_of(&reply), None);
        let read = parse_answer(&reply);
        assert_eq!((read.id, read.rcode), (9, Rcode::NotImp as u8));
    }

    #[test]
    fn edns_sets_the_size_and_answers_bad_versions() {
        let parsed = Query::parse(&query(1, "a.internal", TYPE_A, Some(4096))).unwrap();
        assert_eq!(parsed.edns, Some((0, 4096)));
        assert_eq!(parsed.limit(Transport::Udp), EDNS_UDP_LIMIT);
        assert_eq!(parsed.limit(Transport::Tcp), TCP_LIMIT);
        let small = Query::parse(&query(1, "a.internal", TYPE_A, Some(100))).unwrap();
        assert_eq!(small.limit(Transport::Udp), CLASSIC_UDP_LIMIT);
        let reply = answer(&parsed, Rcode::NoError, &[], 5, false, EDNS_UDP_LIMIT);
        assert_eq!(parse_answer(&reply).opt, Some((EDNS_UDP_LIMIT as u16, 0)));

        let mut v1 = query(1, "a.internal", TYPE_A, Some(1232));
        let len = v1.len();
        v1[len - 5] = 1; // the version byte of the OPT TTL
        let parsed = Query::parse(&v1).unwrap();
        assert_eq!(parsed.edns, Some((1, 1232)));
        let reply = answer(
            &parsed,
            Rcode::NoError,
            &[Record::Address("10.0.0.1".parse().unwrap())],
            5,
            false,
            EDNS_UDP_LIMIT,
        );
        let read = parse_answer(&reply);
        assert!(read.records.is_empty());
        assert_eq!(read.opt, Some((EDNS_UDP_LIMIT as u16, 1)));
    }

    #[test]
    fn sets_tc_when_records_do_not_fit() {
        let parsed = Query::parse(&query(1, "a.internal", TYPE_AAAA, None)).unwrap();
        let records: Vec<Record> = (0..32u16)
            .map(|i| Record::Address(IpAddr::V6([0xfd00, 0, 0, 0, 0, 0, 0, i].into())))
            .collect();
        let reply = answer(
            &parsed,
            Rcode::NoError,
            &records,
            5,
            false,
            CLASSIC_UDP_LIMIT,
        );
        assert!(reply.len() <= CLASSIC_UDP_LIMIT);
        let read = parse_answer(&reply);
        assert!(read.tc);
        assert!(!read.records.is_empty() && read.records.len() < 32);
        let reply = answer(&parsed, Rcode::NoError, &records, 5, false, TCP_LIMIT);
        let read = parse_answer(&reply);
        assert!(!read.tc);
        assert_eq!(read.records.len(), 32);
        let reply = answer(&parsed, Rcode::NoError, &records, 5, true, TCP_LIMIT);
        assert!(parse_answer(&reply).tc);
    }
}
