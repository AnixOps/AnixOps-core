//! Messages on the reliable channel of a backbone link (spec §17.3.7,
//! appendix A): `type(u8) ‖ payload`.

use std::fmt;

use super::region::{parse_summary_prefix, RegionId};
use super::BackboneId;
use crate::net::IpNet;
use crate::wire::pb::{PbError, Reader, Writer};

/// Largest message including the type byte (appendix A.1).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Most prefixes in one RegionAdvert (appendix A.2).
pub const MAX_PREFIXES: usize = 1024;
/// Most entries in one LinkState (appendix A.3).
pub const MAX_LINKS: usize = 256;
/// Largest `cost_milli` (appendix A.3).
pub const MAX_COST_MILLI: u32 = 0xFFFF_FFFE;
/// Probe payload length (appendix A.4).
pub const PROBE_LEN: usize = 16;

/// Message types (spec §17.3.7).
pub mod kind {
    pub const REGION_ADVERT: u8 = 1;
    pub const LINK_STATE: u8 = 2;
    pub const LINK_PROBE: u8 = 3;
    pub const LINK_PROBE_ACK: u8 = 4;
    pub const RELAY_UNREACHABLE: u8 = 5;
    pub const NAME_ADVERT: u8 = 6;
}

/// Lifetime bounds and defaults (appendix A.2, A.3).
pub const REGION_ADVERT_LIFETIME_S: u32 = 90;
pub const LINK_STATE_LIFETIME_S: u32 = 60;
pub const MIN_LIFETIME_S: u32 = 30;
pub const MAX_LIFETIME_S: u32 = 600;

fn lifetime(raw: u32, default: u32) -> u32 {
    if raw == 0 {
        default
    } else {
        raw.clamp(MIN_LIFETIME_S, MAX_LIFETIME_S)
    }
}

/// RegionAdvert (appendix A.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionAdvert {
    pub origin: BackboneId,
    pub region: RegionId,
    pub seq: u64,
    pub prefixes: Vec<IpNet>,
    pub reachable: bool,
    /// Already defaulted and clamped.
    pub lifetime_s: u32,
}

/// One neighbour in a LinkState (appendix A.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkCost {
    pub neighbor: BackboneId,
    pub cost_milli: u32,
    pub loss_ppm: Option<u32>,
}

/// LinkState (appendix A.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    pub origin: BackboneId,
    pub seq: u64,
    pub links: Vec<LinkCost>,
    /// Already defaulted and clamped.
    pub lifetime_s: u32,
}

/// LinkProbe and LinkProbeAck payload (appendix A.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub seq: u64,
    pub sent_us: u64,
}

/// One message of the reliable channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    RegionAdvert(RegionAdvert),
    LinkState(LinkState),
    Probe(Probe),
    ProbeAck(Probe),
    /// The sender could not deliver to this region as a transit (A.5).
    RelayUnreachable {
        region: RegionId,
    },
    /// A type this module does not handle itself (NameAdvert, or one not
    /// assigned yet): the caller counts or dispatches it.
    Other {
        kind: u8,
        payload: Vec<u8>,
    },
}

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Empty,
    TooLong,
    Pb(PbError),
    /// A required field is missing.
    Missing(u32),
    /// A field breaks its constraint.
    Invalid(u32),
    /// A repeated field has too many entries.
    TooMany(u32),
    /// A probe payload is not 16 bytes.
    BadProbe,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Empty => f.write_str("backbone message is empty"),
            DecodeError::TooLong => f.write_str("backbone message is too long"),
            DecodeError::Pb(e) => write!(f, "backbone message: {e}"),
            DecodeError::Missing(n) => write!(f, "backbone message misses field {n}"),
            DecodeError::Invalid(n) => write!(f, "backbone message field {n} is invalid"),
            DecodeError::TooMany(n) => write!(f, "backbone message field {n} has too many entries"),
            DecodeError::BadProbe => f.write_str("backbone probe has the wrong length"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<PbError> for DecodeError {
    fn from(e: PbError) -> Self {
        DecodeError::Pb(e)
    }
}

impl Message {
    /// The type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Message::RegionAdvert(_) => kind::REGION_ADVERT,
            Message::LinkState(_) => kind::LINK_STATE,
            Message::Probe(_) => kind::LINK_PROBE,
            Message::ProbeAck(_) => kind::LINK_PROBE_ACK,
            Message::RelayUnreachable { .. } => kind::RELAY_UNREACHABLE,
            Message::Other { kind, .. } => *kind,
        }
    }

    /// `type ‖ payload`. The caller checks the result against
    /// [`MAX_MESSAGE`] and the link's control cap before sending.
    pub fn encode(&self) -> Vec<u8> {
        let payload = match self {
            Message::RegionAdvert(m) => {
                let mut w = Writer::new();
                w.u32(1, m.origin).str(2, m.region.as_str()).u64(3, m.seq);
                for prefix in &m.prefixes {
                    w.opt_bytes(4, prefix.to_string().as_bytes());
                }
                w.bool(5, m.reachable).u32(6, m.lifetime_s);
                w.finish()
            }
            Message::LinkState(m) => {
                let mut w = Writer::new();
                w.u32(1, m.origin).u64(2, m.seq);
                for link in &m.links {
                    let mut inner = Writer::new();
                    inner.u32(1, link.neighbor).opt_u32(2, link.cost_milli);
                    if let Some(loss) = link.loss_ppm {
                        inner.opt_u32(3, loss);
                    }
                    w.message(3, &inner.finish());
                }
                w.u32(4, m.lifetime_s);
                w.finish()
            }
            Message::Probe(p) | Message::ProbeAck(p) => {
                let mut out = Vec::with_capacity(PROBE_LEN);
                out.extend_from_slice(&p.seq.to_be_bytes());
                out.extend_from_slice(&p.sent_us.to_be_bytes());
                out
            }
            Message::RelayUnreachable { region } => {
                let mut w = Writer::new();
                w.str(1, region.as_str());
                w.finish()
            }
            Message::Other { payload, .. } => payload.clone(),
        };
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(self.kind());
        out.extend_from_slice(&payload);
        out
    }

    /// Decodes and checks one message against appendix A. Membership
    /// (whether `origin` is a member, whether its region matches) is checked
    /// by the topology, not here.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        let (&kind, payload) = bytes.split_first().ok_or(DecodeError::Empty)?;
        if bytes.len() > MAX_MESSAGE {
            return Err(DecodeError::TooLong);
        }
        Ok(match kind {
            kind::REGION_ADVERT => Message::RegionAdvert(decode_region_advert(payload)?),
            kind::LINK_STATE => Message::LinkState(decode_link_state(payload)?),
            kind::LINK_PROBE => Message::Probe(decode_probe(payload)?),
            kind::LINK_PROBE_ACK => Message::ProbeAck(decode_probe(payload)?),
            kind::RELAY_UNREACHABLE => decode_relay_unreachable(payload)?,
            other => Message::Other {
                kind: other,
                payload: payload.to_vec(),
            },
        })
    }
}

fn region(value: &str, field: u32) -> Result<RegionId, DecodeError> {
    RegionId::parse(value).ok_or(DecodeError::Invalid(field))
}

fn decode_region_advert(payload: &[u8]) -> Result<RegionAdvert, DecodeError> {
    let mut origin = 0u32;
    let mut region_id = None;
    let mut seq = 0u64;
    let mut prefixes = Vec::new();
    let mut reachable = false;
    let mut lifetime_s = 0u32;
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => origin = value.u32(1)?,
            2 => region_id = Some(region(value.str(2)?, 2)?),
            3 => seq = value.u64(3)?,
            4 => {
                if prefixes.len() >= MAX_PREFIXES {
                    return Err(DecodeError::TooMany(4));
                }
                let net = parse_summary_prefix(value.str(4)?).ok_or(DecodeError::Invalid(4))?;
                prefixes.push(net);
            }
            5 => reachable = value.bool(5)?,
            6 => lifetime_s = value.u32(6)?,
            _ => {}
        }
    }
    if origin == 0 {
        return Err(DecodeError::Missing(1));
    }
    let region_id = region_id.ok_or(DecodeError::Missing(2))?;
    if seq == 0 {
        return Err(DecodeError::Missing(3));
    }
    Ok(RegionAdvert {
        origin,
        region: region_id,
        seq,
        prefixes,
        reachable,
        lifetime_s: lifetime(lifetime_s, REGION_ADVERT_LIFETIME_S),
    })
}

fn decode_link_cost(payload: &[u8]) -> Result<LinkCost, DecodeError> {
    let mut neighbor = 0u32;
    let mut cost = None;
    let mut loss_ppm = None;
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => neighbor = value.u32(1)?,
            2 => cost = Some(value.u32(2)?),
            3 => loss_ppm = Some(value.u32(3)?),
            _ => {}
        }
    }
    if neighbor == 0 {
        return Err(DecodeError::Missing(1));
    }
    let cost_milli = cost.ok_or(DecodeError::Missing(2))?;
    if cost_milli > MAX_COST_MILLI {
        return Err(DecodeError::Invalid(2));
    }
    if loss_ppm.is_some_and(|loss| loss > 1_000_000) {
        return Err(DecodeError::Invalid(3));
    }
    Ok(LinkCost {
        neighbor,
        cost_milli,
        loss_ppm,
    })
}

fn decode_link_state(payload: &[u8]) -> Result<LinkState, DecodeError> {
    let mut origin = 0u32;
    let mut seq = 0u64;
    let mut links: Vec<LinkCost> = Vec::new();
    let mut lifetime_s = 0u32;
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next()? {
        match field {
            1 => origin = value.u32(1)?,
            2 => seq = value.u64(2)?,
            3 => {
                if links.len() >= MAX_LINKS {
                    return Err(DecodeError::TooMany(3));
                }
                links.push(decode_link_cost(value.bytes(3)?)?);
            }
            4 => lifetime_s = value.u32(4)?,
            _ => {}
        }
    }
    if origin == 0 {
        return Err(DecodeError::Missing(1));
    }
    if seq == 0 {
        return Err(DecodeError::Missing(2));
    }
    let mut seen = std::collections::BTreeSet::new();
    for link in &links {
        if link.neighbor == origin || !seen.insert(link.neighbor) {
            return Err(DecodeError::Invalid(3));
        }
    }
    Ok(LinkState {
        origin,
        seq,
        links,
        lifetime_s: lifetime(lifetime_s, LINK_STATE_LIFETIME_S),
    })
}

fn decode_probe(payload: &[u8]) -> Result<Probe, DecodeError> {
    if payload.len() != PROBE_LEN {
        return Err(DecodeError::BadProbe);
    }
    let seq = u64::from_be_bytes(payload[..8].try_into().expect("8 bytes"));
    let sent_us = u64::from_be_bytes(payload[8..].try_into().expect("8 bytes"));
    Ok(Probe { seq, sent_us })
}

fn decode_relay_unreachable(payload: &[u8]) -> Result<Message, DecodeError> {
    let mut region_id = None;
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next()? {
        if field == 1 {
            region_id = Some(region(value.str(1)?, 1)?);
        }
    }
    Ok(Message::RelayUnreachable {
        region: region_id.ok_or(DecodeError::Missing(1))?,
    })
}

/// Per-publisher sequence numbers (appendix A.1): start at the current Unix
/// time in milliseconds and never fall behind it.
#[derive(Clone, Copy, Debug)]
pub struct SeqCounter {
    last: u64,
}

impl SeqCounter {
    /// `unix_ms` is the current Unix time in milliseconds.
    pub fn new(unix_ms: u64) -> Self {
        Self {
            last: unix_ms.max(1).saturating_sub(1),
        }
    }

    /// The next sequence number.
    pub fn next(&mut self, unix_ms: u64) -> u64 {
        self.last = self.last.saturating_add(1).max(unix_ms).max(1);
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(s: &str) -> RegionId {
        RegionId::parse(s).unwrap()
    }

    fn net(s: &str) -> IpNet {
        parse_summary_prefix(s).unwrap()
    }

    fn advert() -> RegionAdvert {
        RegionAdvert {
            origin: 11,
            region: rid("eu"),
            seq: 1_700_000_000_000,
            prefixes: vec![net("10.20.0.0/16"), net("fd00:20::/32")],
            reachable: true,
            lifetime_s: 90,
        }
    }

    #[test]
    fn region_advert_round_trips() {
        let m = Message::RegionAdvert(advert());
        let bytes = m.encode();
        assert_eq!(bytes[0], kind::REGION_ADVERT);
        assert_eq!(Message::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_state_round_trips() {
        let m = Message::LinkState(LinkState {
            origin: 11,
            seq: 5,
            links: vec![
                LinkCost {
                    neighbor: 21,
                    cost_milli: 0,
                    loss_ppm: None,
                },
                LinkCost {
                    neighbor: 31,
                    cost_milli: 152_500,
                    loss_ppm: Some(20_000),
                },
            ],
            lifetime_s: 60,
        });
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn probes_and_relay_unreachable_round_trip() {
        let probe = Probe {
            seq: 7,
            sent_us: 123_456,
        };
        for m in [
            Message::Probe(probe),
            Message::ProbeAck(probe),
            Message::RelayUnreachable { region: rid("na") },
        ] {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
        assert_eq!(Message::Probe(probe).encode().len(), 1 + PROBE_LEN);
        assert_eq!(
            Message::decode(&[kind::LINK_PROBE, 0, 0, 0]),
            Err(DecodeError::BadProbe)
        );
    }

    #[test]
    fn unknown_and_name_types_pass_through() {
        let m = Message::decode(&[kind::NAME_ADVERT, 1, 2]).unwrap();
        assert_eq!(
            m,
            Message::Other {
                kind: kind::NAME_ADVERT,
                payload: vec![1, 2]
            }
        );
        assert!(matches!(
            Message::decode(&[200]).unwrap(),
            Message::Other { kind: 200, .. }
        ));
        assert_eq!(Message::decode(&[]), Err(DecodeError::Empty));
    }

    #[test]
    fn lifetimes_default_and_clamp() {
        let mut a = advert();
        for (raw, want) in [(0, 90), (1, 30), (45, 45), (10_000, 600)] {
            a.lifetime_s = raw;
            let Message::RegionAdvert(back) =
                Message::decode(&Message::RegionAdvert(a.clone()).encode()).unwrap()
            else {
                panic!("wrong type");
            };
            assert_eq!(back.lifetime_s, want, "raw {raw}");
        }
    }

    #[test]
    fn region_advert_constraints() {
        // Missing origin, region, seq.
        for (field, want) in [(1, 1), (2, 2), (3, 3)] {
            let a = advert();
            let mut w = Writer::new();
            if field != 1 {
                w.u32(1, a.origin);
            }
            if field != 2 {
                w.str(2, a.region.as_str());
            }
            if field != 3 {
                w.u64(3, a.seq);
            }
            let mut bytes = vec![kind::REGION_ADVERT];
            bytes.extend(w.finish());
            assert_eq!(Message::decode(&bytes), Err(DecodeError::Missing(want)));
        }
        // A public prefix or a non-canonical one refuses the whole message.
        for bad in ["8.8.8.0/24", "10.20.0.1/16", "10.0.0.0/7"] {
            let mut w = Writer::new();
            w.u32(1, 11)
                .str(2, "eu")
                .u64(3, 1)
                .opt_bytes(4, bad.as_bytes());
            let mut bytes = vec![kind::REGION_ADVERT];
            bytes.extend(w.finish());
            assert_eq!(
                Message::decode(&bytes),
                Err(DecodeError::Invalid(4)),
                "{bad}"
            );
        }
        // Bad region ID.
        let mut w = Writer::new();
        w.u32(1, 11).str(2, "EU").u64(3, 1);
        let mut bytes = vec![kind::REGION_ADVERT];
        bytes.extend(w.finish());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::Invalid(2)));
        // Too many prefixes.
        let mut a = advert();
        a.prefixes = (0..=MAX_PREFIXES)
            .map(|i| net(&format!("10.{}.{}.0/24", i / 256, i % 256)))
            .collect();
        assert_eq!(
            Message::decode(&Message::RegionAdvert(a).encode()),
            Err(DecodeError::TooMany(4))
        );
    }

    #[test]
    fn link_state_constraints() {
        let state = |links: Vec<LinkCost>| {
            Message::LinkState(LinkState {
                origin: 11,
                seq: 1,
                links,
                lifetime_s: 60,
            })
            .encode()
        };
        let link = |neighbor, cost_milli, loss_ppm| LinkCost {
            neighbor,
            cost_milli,
            loss_ppm,
        };
        assert_eq!(
            Message::decode(&state(vec![link(11, 1, None)])),
            Err(DecodeError::Invalid(3))
        );
        assert_eq!(
            Message::decode(&state(vec![link(21, 1, None), link(21, 2, None)])),
            Err(DecodeError::Invalid(3))
        );
        assert_eq!(
            Message::decode(&state(vec![link(21, u32::MAX, None)])),
            Err(DecodeError::Invalid(2))
        );
        assert_eq!(
            Message::decode(&state(vec![link(21, 1, Some(1_000_001))])),
            Err(DecodeError::Invalid(3))
        );
        assert_eq!(
            Message::decode(&state(
                (1..=MAX_LINKS as u32 + 1)
                    .map(|n| link(n + 100, 1, None))
                    .collect()
            )),
            Err(DecodeError::TooMany(3))
        );
        // A missing cost is refused even though 0 is a valid cost.
        let mut inner = Writer::new();
        inner.u32(1, 21);
        let mut w = Writer::new();
        w.u32(1, 11).u64(2, 1).message(3, &inner.finish());
        let mut bytes = vec![kind::LINK_STATE];
        bytes.extend(w.finish());
        assert_eq!(Message::decode(&bytes), Err(DecodeError::Missing(2)));
    }

    #[test]
    fn oversized_messages_are_refused() {
        let mut bytes = vec![kind::NAME_ADVERT];
        bytes.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Message::decode(&bytes), Err(DecodeError::TooLong));
    }

    #[test]
    fn sequence_numbers_start_at_unix_ms_and_only_grow() {
        let mut seq = SeqCounter::new(1_000);
        assert_eq!(seq.next(1_000), 1_000);
        assert_eq!(seq.next(1_000), 1_001);
        assert_eq!(seq.next(990), 1_002);
        assert_eq!(seq.next(5_000), 5_000);
        let mut zero = SeqCounter::new(0);
        assert_eq!(zero.next(0), 1);
    }
}
