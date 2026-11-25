//! Connection tracking entries of the bridge (spec §15.12 items 2–4 and 9;
//! recheck #356 X3).
//!
//! Source translation and "replies only" both live in the kernel's
//! connection tracking table. Taking a source off the allow list, or a
//! route off the list, or removing the rules altogether leaves the entries
//! of connections already set up; their translation and replies would keep
//! working until the entries time out (days for TCP). So whenever the
//! bridge narrows or goes away, the entries whose original source is in a
//! removed source range and whose original destination is in a removed or
//! remaining route are deleted, and only then the change counts as applied.
//!
//! This module talks ctnetlink directly (no `conntrack` program needed):
//! one dump per address family, then one delete per selected entry, by the
//! entry's own original tuple and zone as the dump gave them. The message
//! encoding and parsing are plain functions, tested without a kernel.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use outbound_mesh::IpNet;

/// `NFNL_SUBSYS_CTNETLINK`.
const SUBSYS_CTNETLINK: u16 = 1;
/// `IPCTNL_MSG_CT_NEW`: what a dump returns.
const MSG_CT_NEW: u16 = 0;
/// `IPCTNL_MSG_CT_GET`.
const MSG_CT_GET: u16 = 1;
/// `IPCTNL_MSG_CT_DELETE`.
const MSG_CT_DELETE: u16 = 2;

pub(crate) const NLM_F_REQUEST: u16 = 0x1;
pub(crate) const NLM_F_ACK: u16 = 0x4;
pub(crate) const NLM_F_DUMP: u16 = 0x300;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;

const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const NLA_HDRLEN: usize = 4;
/// Attribute type without `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = 0x3fff;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_ZONE: u16 = 18;
const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// One tracked connection as far as the bridge cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub family: u8,
    pub source: IpAddr,
    pub destination: IpAddr,
    /// The `CTA_TUPLE_ORIG` attribute as received, header included; sent
    /// back unchanged to delete exactly this entry.
    orig: Vec<u8>,
    /// The `CTA_ZONE` attribute as received, if any.
    zone: Option<Vec<u8>>,
}

/// A flow for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn test_flow(source: IpAddr, destination: IpAddr) -> Flow {
    Flow {
        family: if source.is_ipv4() { AF_INET } else { AF_INET6 },
        source,
        destination,
        orig: Vec::new(),
        zone: None,
    }
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn header(buf: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, family: u8) {
    buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set below
    buf.extend_from_slice(&((SUBSYS_CTNETLINK << 8) | kind).to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel
    buf.push(family);
    buf.push(0); // NFNETLINK_V0
    buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
}

fn finish(mut buf: Vec<u8>) -> Vec<u8> {
    let len = buf.len() as u32;
    buf[..4].copy_from_slice(&len.to_ne_bytes());
    buf
}

/// The request that dumps every entry of `family`.
pub fn dump_request(family: u8, seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NLMSG_HDRLEN + NFGENMSG_LEN);
    header(
        &mut buf,
        MSG_CT_GET,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        family,
    );
    finish(buf)
}

/// The request that deletes `flow`, acknowledged.
pub fn delete_request(flow: &Flow, seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NLMSG_HDRLEN + NFGENMSG_LEN + flow.orig.len() + 8);
    header(
        &mut buf,
        MSG_CT_DELETE,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        flow.family,
    );
    buf.extend_from_slice(&flow.orig);
    buf.resize(align4(buf.len()), 0);
    if let Some(zone) = &flow.zone {
        buf.extend_from_slice(zone);
        buf.resize(align4(buf.len()), 0);
    }
    finish(buf)
}

/// Attributes in `data`: (type without flags, payload, whole attribute).
fn attributes(data: &[u8]) -> impl Iterator<Item = (u16, &[u8], &[u8])> {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.len() < NLA_HDRLEN {
            return None;
        }
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        if len < NLA_HDRLEN || len > rest.len() {
            return None;
        }
        let kind = u16::from_ne_bytes([rest[2], rest[3]]) & NLA_TYPE_MASK;
        let whole = &rest[..len];
        let payload = &rest[NLA_HDRLEN..len];
        rest = &rest[align4(len).min(rest.len())..];
        Some((kind, payload, whole))
    })
}

fn find(data: &[u8], kind: u16) -> Option<(&[u8], &[u8])> {
    attributes(data)
        .find(|(k, _, _)| *k == kind)
        .map(|(_, payload, whole)| (payload, whole))
}

fn address(payload: &[u8]) -> Option<IpAddr> {
    match payload.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(payload);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Parses one `IPCTNL_MSG_CT_NEW` body (after the netlink header).
fn parse_flow(body: &[u8]) -> Option<Flow> {
    if body.len() < NFGENMSG_LEN {
        return None;
    }
    let family = body[0];
    let attrs = &body[NFGENMSG_LEN..];
    let (orig_payload, orig_whole) = find(attrs, CTA_TUPLE_ORIG)?;
    let (ip, _) = find(orig_payload, CTA_TUPLE_IP)?;
    let (src_kind, dst_kind) = if family == AF_INET6 {
        (CTA_IP_V6_SRC, CTA_IP_V6_DST)
    } else {
        (CTA_IP_V4_SRC, CTA_IP_V4_DST)
    };
    let source = address(find(ip, src_kind)?.0)?;
    let destination = address(find(ip, dst_kind)?.0)?;
    let zone = find(attrs, CTA_ZONE).map(|(_, whole)| whole.to_vec());
    Some(Flow {
        family,
        source,
        destination,
        orig: orig_whole.to_vec(),
        zone,
    })
}

/// What one received datagram holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    pub flows: Vec<Flow>,
    /// `NLMSG_DONE` seen: the dump is complete.
    pub done: bool,
    /// Errors from `NLMSG_ERROR` (negative errno; 0 is an acknowledgement).
    pub errors: Vec<i32>,
}

/// Parses the netlink messages of one datagram.
pub fn parse_datagram(data: &[u8]) -> io::Result<Received> {
    let mut received = Received::default();
    let mut rest = data;
    while rest.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink message",
            ));
        }
        let kind = u16::from_ne_bytes([rest[4], rest[5]]);
        let body = &rest[NLMSG_HDRLEN..len];
        match kind {
            NLMSG_DONE => received.done = true,
            NLMSG_ERROR => {
                if body.len() >= 4 {
                    received
                        .errors
                        .push(i32::from_ne_bytes([body[0], body[1], body[2], body[3]]));
                }
            }
            _ if kind == ((SUBSYS_CTNETLINK << 8) | MSG_CT_NEW) => {
                if let Some(flow) = parse_flow(body) {
                    received.flows.push(flow);
                }
            }
            _ => {}
        }
        rest = &rest[align4(len).min(rest.len())..];
    }
    Ok(received)
}

/// The entries to delete: original source in one of `sources` and original
/// destination in one of `destinations`.
pub fn select<'a>(flows: &'a [Flow], sources: &[IpNet], destinations: &[IpNet]) -> Vec<&'a Flow> {
    flows
        .iter()
        .filter(|flow| sources.iter().any(|net| net.contains(flow.source)))
        .filter(|flow| {
            destinations
                .iter()
                .any(|net| net.contains(flow.destination))
        })
        .collect()
}

/// The source and destination ranges whose entries must go when the bridge
/// changes from `old` to `new` (`None`: removed). A source that left the
/// list loses its entries towards every old route; a route that left the
/// list loses the entries of every old source.
pub fn narrowed(
    old_allow: &[IpNet],
    old_routes: &[IpNet],
    new: Option<(&[IpNet], &[IpNet])>,
) -> Vec<(Vec<IpNet>, Vec<IpNet>)> {
    let Some((new_allow, new_routes)) = new else {
        return vec![(old_allow.to_vec(), old_routes.to_vec())];
    };
    let covered = |net: &IpNet, list: &[IpNet]| list.iter().any(|other| other.covers(net));
    let gone_allow: Vec<IpNet> = old_allow
        .iter()
        .filter(|net| !covered(net, new_allow))
        .copied()
        .collect();
    let gone_routes: Vec<IpNet> = old_routes
        .iter()
        .filter(|net| !covered(net, new_routes))
        .copied()
        .collect();
    let mut pairs = Vec::new();
    if !gone_allow.is_empty() {
        pairs.push((gone_allow, old_routes.to_vec()));
    }
    if !gone_routes.is_empty() {
        pairs.push((old_allow.to_vec(), gone_routes));
    }
    pairs
}

#[cfg(target_os = "linux")]
pub(crate) mod sys {
    //! The ctnetlink socket.

    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{delete_request, dump_request, parse_datagram, Flow, AF_INET, AF_INET6};

    const NETLINK_NETFILTER: libc::c_int = 12;

    struct Socket {
        fd: OwnedFd,
        seq: u32,
    }

    impl Socket {
        fn open() -> io::Result<Self> {
            // SAFETY: plain socket call; the result is checked.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    NETLINK_NETFILTER,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a new descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: zeroed sockaddr_nl is valid; the kernel assigns the port.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: `addr` is a valid sockaddr_nl of the given size.
            let bound = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    std::ptr::addr_of!(addr).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if bound < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd, seq: 1 })
        }

        fn send(&mut self, message: &[u8]) -> io::Result<()> {
            // SAFETY: `message` is a valid buffer of its length.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    message.as_ptr().cast(),
                    message.len(),
                    0,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            // SAFETY: `buffer` is a valid writable buffer of its length.
            let got = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(got as usize)
        }

        fn next_seq(&mut self) -> u32 {
            self.seq = self.seq.wrapping_add(1);
            self.seq
        }
    }

    fn errno(code: i32) -> io::Error {
        io::Error::from_raw_os_error(-code)
    }

    /// Every tracked connection of both families.
    pub fn flows() -> io::Result<Vec<Flow>> {
        let mut socket = Socket::open()?;
        let mut buffer = vec![0u8; 64 * 1024];
        let mut flows = Vec::new();
        for family in [AF_INET, AF_INET6] {
            let seq = socket.next_seq();
            socket.send(&dump_request(family, seq))?;
            loop {
                let got = socket.recv(&mut buffer)?;
                let received = parse_datagram(&buffer[..got])?;
                if let Some(code) = received.errors.iter().find(|code| **code != 0) {
                    return Err(errno(*code));
                }
                flows.extend(received.flows);
                if received.done || !received.errors.is_empty() {
                    break;
                }
            }
        }
        Ok(flows)
    }

    /// Deletes each flow; an entry already gone (`ENOENT`) is not an error.
    pub fn delete(flows: &[&Flow]) -> io::Result<()> {
        if flows.is_empty() {
            return Ok(());
        }
        let mut socket = Socket::open()?;
        let mut buffer = vec![0u8; 8 * 1024];
        for flow in flows {
            let seq = socket.next_seq();
            socket.send(&delete_request(flow, seq))?;
            loop {
                let got = socket.recv(&mut buffer)?;
                let received = parse_datagram(&buffer[..got])?;
                if let Some(code) = received.errors.first() {
                    if *code != 0 && *code != -libc::ENOENT {
                        return Err(errno(*code));
                    }
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((NLA_HDRLEN + payload.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(align4(out.len()), 0);
        out
    }

    fn nested(kind: u16, parts: &[Vec<u8>]) -> Vec<u8> {
        attr(kind | 0x8000, &parts.concat())
    }

    fn message(kind: u16, family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        header(&mut buf, kind, 0x2, 7, family);
        buf.extend_from_slice(&attrs.concat());
        finish(buf)
    }

    fn v4_flow_message(src: [u8; 4], dst: [u8; 4], zone: Option<u16>) -> Vec<u8> {
        let ip = nested(
            CTA_TUPLE_IP,
            &[attr(CTA_IP_V4_SRC, &src), attr(CTA_IP_V4_DST, &dst)],
        );
        let proto = nested(2, &[attr(1, &[1]), attr(4, &7u16.to_be_bytes())]);
        let orig = nested(CTA_TUPLE_ORIG, &[ip.clone(), proto.clone()]);
        let reply = nested(2, &[ip, proto]);
        let mut attrs = vec![orig, reply, attr(3, &8u32.to_be_bytes())];
        if let Some(zone) = zone {
            attrs.push(attr(CTA_ZONE, &zone.to_be_bytes()));
        }
        message(MSG_CT_NEW, AF_INET, &attrs)
    }

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    #[test]
    fn requests_are_laid_out_as_ctnetlink_expects() {
        let dump = dump_request(AF_INET6, 9);
        assert_eq!(dump.len(), 20);
        assert_eq!(u32::from_ne_bytes(dump[..4].try_into().unwrap()), 20);
        assert_eq!(
            u16::from_ne_bytes([dump[4], dump[5]]),
            (1 << 8) | MSG_CT_GET
        );
        assert_eq!(u16::from_ne_bytes([dump[6], dump[7]]), 0x301);
        assert_eq!(u32::from_ne_bytes(dump[8..12].try_into().unwrap()), 9);
        assert_eq!(&dump[16..20], &[AF_INET6, 0, 0, 0]);
    }

    #[test]
    fn a_dump_is_parsed_and_a_delete_carries_the_tuple_and_zone_back() {
        let mut datagram = v4_flow_message([10, 150, 0, 2], [100, 100, 0, 5], Some(3));
        datagram.extend(v4_flow_message([10, 150, 0, 9], [192, 168, 1, 1], None));
        let mut done = Vec::new();
        header(&mut done, 0, 0x2, 7, 0);
        let mut done = finish(done);
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        datagram.extend(done);

        let received = parse_datagram(&datagram).unwrap();
        assert!(received.done);
        assert_eq!(received.flows.len(), 2);
        let flow = &received.flows[0];
        assert_eq!(flow.source, "10.150.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(flow.destination, "100.100.0.5".parse::<IpAddr>().unwrap());
        assert!(flow.zone.is_some());
        assert!(received.flows[1].zone.is_none());

        let delete = delete_request(flow, 11);
        assert_eq!(
            u16::from_ne_bytes([delete[4], delete[5]]),
            (1 << 8) | MSG_CT_DELETE
        );
        assert_eq!(u16::from_ne_bytes([delete[6], delete[7]]), 0x5);
        assert_eq!(delete[16], AF_INET);
        let attrs: Vec<u16> = attributes(&delete[20..]).map(|(k, _, _)| k).collect();
        assert_eq!(attrs, [CTA_TUPLE_ORIG, CTA_ZONE]);
        assert_eq!(&delete[20..20 + flow.orig.len()], flow.orig.as_slice());
        assert_eq!(
            u32::from_ne_bytes(delete[..4].try_into().unwrap()) as usize,
            delete.len()
        );
    }

    #[test]
    fn ipv6_flows_are_parsed() {
        let src: Ipv6Addr = "fd00:150::2".parse().unwrap();
        let dst: Ipv6Addr = "fd7a:115c:a1e0::9".parse().unwrap();
        let ip = nested(
            CTA_TUPLE_IP,
            &[
                attr(CTA_IP_V6_SRC, &src.octets()),
                attr(CTA_IP_V6_DST, &dst.octets()),
            ],
        );
        let datagram = message(MSG_CT_NEW, AF_INET6, &[nested(CTA_TUPLE_ORIG, &[ip])]);
        let received = parse_datagram(&datagram).unwrap();
        assert_eq!(received.flows[0].source, IpAddr::V6(src));
        assert_eq!(received.flows[0].destination, IpAddr::V6(dst));
    }

    #[test]
    fn errors_and_damage_are_reported() {
        let mut error = Vec::new();
        header(&mut error, 0, 0, 7, 0);
        error.truncate(16);
        error.extend_from_slice(&(-2i32).to_ne_bytes());
        error.extend_from_slice(&[0u8; 16]);
        let mut error = finish(error);
        error[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert_eq!(parse_datagram(&error).unwrap().errors, [-2]);

        let mut cut = v4_flow_message([10, 0, 0, 1], [10, 0, 0, 2], None);
        cut.truncate(cut.len() - 4);
        assert!(parse_datagram(&cut).is_err());

        // A flow without addresses is skipped, not misread.
        let empty = message(MSG_CT_NEW, AF_INET, &[nested(CTA_TUPLE_ORIG, &[])]);
        assert!(parse_datagram(&empty).unwrap().flows.is_empty());
    }

    #[test]
    fn only_flows_from_removed_sources_or_to_removed_routes_are_selected() {
        let mut datagram = Vec::new();
        for (src, dst) in [
            ([10, 150, 0, 2], [100, 100, 0, 5]),
            ([10, 150, 0, 3], [100, 100, 0, 5]),
            ([10, 150, 0, 2], [100, 100, 0, 6]),
            ([10, 127, 0, 4], [100, 100, 0, 5]),
            ([100, 100, 0, 5], [100, 100, 0, 1]),
        ] {
            datagram.extend(v4_flow_message(src, dst, None));
        }
        let flows = parse_datagram(&datagram).unwrap().flows;
        let old_allow = [
            net("10.127.0.0/24"),
            net("10.150.0.2/32"),
            net("10.150.0.3/32"),
        ];
        let old_routes = [net("100.100.0.5/32"), net("100.100.0.6/32")];

        // 10.150.0.3 leaves the list: only its flows go.
        let new_allow = [net("10.127.0.0/24"), net("10.150.0.2/32")];
        let pairs = narrowed(&old_allow, &old_routes, Some((&new_allow, &old_routes)));
        let selected: Vec<IpAddr> = pairs
            .iter()
            .flat_map(|(s, d)| select(&flows, s, d))
            .map(|flow| flow.source)
            .collect();
        assert_eq!(selected, ["10.150.0.3".parse::<IpAddr>().unwrap()]);

        // A route leaves: every source's flows to it go.
        let new_routes = [net("100.100.0.5/32")];
        let pairs = narrowed(&old_allow, &old_routes, Some((&old_allow, &new_routes)));
        let selected: Vec<IpAddr> = pairs
            .iter()
            .flat_map(|(s, d)| select(&flows, s, d))
            .map(|flow| flow.destination)
            .collect();
        assert_eq!(selected, ["100.100.0.6".parse::<IpAddr>().unwrap()]);

        // Nothing narrowed: nothing goes.
        assert!(narrowed(&old_allow, &old_routes, Some((&old_allow, &old_routes))).is_empty());

        // Removed: every bridged flow goes, the external side's own flow
        // to the bridge does not.
        let pairs = narrowed(&old_allow, &old_routes, None);
        let selected: usize = pairs.iter().map(|(s, d)| select(&flows, s, d).len()).sum();
        assert_eq!(selected, 4);
    }
}
