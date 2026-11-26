//! Linux side of [`super`]: routes from a netlink dump of every routing
//! table, interfaces from `if_nameindex` and `/sys/class/net`.

use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use outbound_mesh::IpNet;

use super::{HostLink, HostRoute};

/// Link type of a device without a link layer (TUN).
const ARPHRD_NONE: u16 = 0xfffe;
const IFF_POINTOPOINT: u32 = 0x10;

const NLMSG_HEADER: usize = 16;
const RTMSG: usize = 12;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const RTN_UNICAST: u8 = 1;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_MULTIPATH: u16 = 9;

fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// The attributes in `bytes` as (type, payload), stopping at the first one
/// that does not fit.
fn attributes(bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut found = Vec::new();
    let mut at = 0;
    while let (Some(length), Some(kind)) = (u16_at(bytes, at), u16_at(bytes, at + 2)) {
        let length = usize::from(length);
        if length < 4 || at + length > bytes.len() {
            break;
        }
        // The top bits are flags (nested, byte order).
        found.push((kind & 0x3fff, &bytes[at + 4..at + length]));
        at += align(length);
    }
    found
}

/// Interfaces of an `RTA_MULTIPATH` payload (a list of `rtnexthop`).
fn next_hops(mut bytes: &[u8]) -> Vec<u32> {
    let mut found = Vec::new();
    while let (Some(length), Some(index)) = (u16_at(bytes, 0), u32_at(bytes, 4)) {
        let length = usize::from(length);
        if length < 8 || length > bytes.len() {
            break;
        }
        found.push(index);
        bytes = &bytes[align(length).min(bytes.len())..];
    }
    found
}

/// One `RTM_NEWROUTE` payload (rtmsg plus attributes). `None` for routes
/// that are not unicast or carry no destination of a known family.
fn parse_route(payload: &[u8]) -> Option<HostRoute> {
    let header = payload.get(..RTMSG)?;
    let family = libc::c_int::from(header[0]);
    let prefix = header[1];
    if header[7] != RTN_UNICAST {
        return None;
    }
    let mut destination = None;
    let mut interfaces = Vec::new();
    for (kind, value) in attributes(&payload[RTMSG..]) {
        match kind {
            RTA_DST => {
                destination = match (family, value.len()) {
                    (libc::AF_INET, 4) => {
                        Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?)))
                    }
                    (libc::AF_INET6, 16) => Some(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(value).ok()?,
                    ))),
                    _ => return None,
                };
            }
            RTA_OIF => interfaces.extend(u32_at(value, 0)),
            RTA_MULTIPATH => interfaces.extend(next_hops(value)),
            _ => {}
        }
    }
    // A route without RTA_DST is a default route (prefix 0).
    let destination = match (destination, family) {
        (Some(address), _) => address,
        (None, libc::AF_INET) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (None, libc::AF_INET6) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => return None,
    };
    Some(HostRoute {
        destination: IpNet::new(destination, prefix)?.trunc(),
        interfaces,
    })
}

/// Splits a buffer of netlink messages. Returns the routes found and whether
/// the dump is finished; a netlink error message becomes an error.
fn parse_messages(mut bytes: &[u8], routes: &mut Vec<HostRoute>) -> io::Result<bool> {
    while bytes.len() >= NLMSG_HEADER {
        let length = u32_at(bytes, 0).unwrap_or(0) as usize;
        let kind = u16_at(bytes, 4).unwrap_or(0);
        if length < NLMSG_HEADER || length > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a truncated routing message",
            ));
        }
        let payload = &bytes[NLMSG_HEADER..length];
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = u32_at(payload, 0).unwrap_or(0) as i32;
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
            RTM_NEWROUTE => routes.extend(parse_route(payload)),
            _ => {}
        }
        bytes = &bytes[align(length).min(bytes.len())..];
    }
    Ok(false)
}

/// The request for a dump of every routing table of `family`.
fn dump_request(family: u8, sequence: u32) -> Vec<u8> {
    let length = (NLMSG_HEADER + RTMSG) as u32;
    let mut request = Vec::with_capacity(length as usize);
    request.extend_from_slice(&length.to_ne_bytes());
    request.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    // rtmsg: family, then zeros (every table, every type).
    request.push(family);
    request.extend_from_slice(&[0u8; RTMSG - 1]);
    request
}

/// Every unicast route of every routing table, IPv4 and IPv6.
pub fn host_routes() -> io::Result<Vec<HostRoute>> {
    // SAFETY: plain socket call; the descriptor is owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor nobody else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut routes = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    for (sequence, family) in [(1u32, libc::AF_INET), (2, libc::AF_INET6)] {
        let request = dump_request(family as u8, sequence);
        // SAFETY: the request buffer is valid for its length; the kernel is
        // the default destination of an unbound netlink socket.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut routes_of_family = Vec::new();
        loop {
            // SAFETY: the buffer is valid for writes of its length.
            let received = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            match parse_messages(&buffer[..received as usize], &mut routes_of_family) {
                Ok(false) if received > 0 => {}
                Ok(_) => break,
                // A host without IPv6 answers the IPv6 dump with an error.
                Err(error)
                    if family == libc::AF_INET6
                        && error.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
                {
                    routes_of_family.clear();
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        routes.append(&mut routes_of_family);
    }
    Ok(routes)
}

/// Link type and flags as the kernel shows them under `/sys/class/net`.
fn link_is_virtual(name: &str) -> bool {
    let read = |file: &str| std::fs::read_to_string(format!("/sys/class/net/{name}/{file}"));
    let link_type = read("type")
        .ok()
        .and_then(|text| text.trim().parse::<u16>().ok());
    let flags = read("flags")
        .ok()
        .and_then(|text| u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok());
    link_type == Some(ARPHRD_NONE) || flags.is_some_and(|flags| flags & IFF_POINTOPOINT != 0)
}

/// Every interface by index.
pub fn host_links() -> io::Result<HashMap<u32, HostLink>> {
    // SAFETY: the list is freed below with `if_freenameindex`.
    let head = unsafe { libc::if_nameindex() };
    if head.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut links = HashMap::new();
    let mut cursor = head;
    loop {
        // SAFETY: `cursor` stays within the list, which ends with a zero entry.
        let entry = unsafe { &*cursor };
        if entry.if_index == 0 || entry.if_name.is_null() {
            break;
        }
        // SAFETY: a non-null name is a C string.
        let name = unsafe { CStr::from_ptr(entry.if_name) }
            .to_string_lossy()
            .into_owned();
        // Names with a path separator cannot come from the kernel; skip them
        // rather than build a path from one.
        if !name.contains('/') && name != "." && name != ".." {
            let is_virtual = link_is_virtual(&name);
            links.insert(entry.if_index, HostLink { name, is_virtual });
        }
        // SAFETY: the next entry exists until the zero entry is reached.
        cursor = unsafe { cursor.add(1) };
    }
    // SAFETY: `head` came from `if_nameindex` and is freed once.
    unsafe { libc::if_freenameindex(head) };
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn route(text: &str, interfaces: &[u32]) -> HostRoute {
        HostRoute {
            destination: net(text),
            interfaces: interfaces.to_vec(),
        }
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((NLMSG_HEADER + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        bytes.extend_from_slice(payload);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn rtmsg(family: u8, prefix: u8, route_type: u8) -> Vec<u8> {
        let mut bytes = vec![family, prefix, 0, 0, 254, 0, 0, route_type];
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }

    #[test]
    fn route_messages_are_parsed() {
        let mut ipv4 = rtmsg(libc::AF_INET as u8, 10, RTN_UNICAST);
        ipv4.extend(attribute(RTA_DST, &[100, 64, 0, 0]));
        ipv4.extend(attribute(RTA_OIF, &3u32.to_ne_bytes()));

        let mut ipv6 = rtmsg(libc::AF_INET6 as u8, 48, RTN_UNICAST);
        let mut address = [0u8; 16];
        address[..6].copy_from_slice(&[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]);
        ipv6.extend(attribute(RTA_DST, &address));
        let mut hops = Vec::new();
        for index in [2u32, 3] {
            hops.extend_from_slice(&8u16.to_ne_bytes());
            hops.extend_from_slice(&[0, 0]);
            hops.extend_from_slice(&index.to_ne_bytes());
        }
        ipv6.extend(attribute(RTA_MULTIPATH, &hops));

        let mut default = rtmsg(libc::AF_INET as u8, 0, RTN_UNICAST);
        default.extend(attribute(RTA_OIF, &2u32.to_ne_bytes()));

        // A local route (type 2) is skipped.
        let mut local = rtmsg(libc::AF_INET as u8, 32, 2);
        local.extend(attribute(RTA_DST, &[127, 0, 0, 1]));

        let mut bytes = Vec::new();
        for payload in [&ipv4, &ipv6, &default, &local] {
            bytes.extend(message(RTM_NEWROUTE, payload));
        }
        let mut routes = Vec::new();
        assert!(!parse_messages(&bytes, &mut routes).unwrap());
        assert_eq!(
            routes,
            vec![
                route("100.64.0.0/10", &[3]),
                route("fd7a:115c:a1e0::/48", &[2, 3]),
                route("0.0.0.0/0", &[2]),
            ]
        );

        let mut done = Vec::new();
        assert!(parse_messages(&message(NLMSG_DONE, &[0u8; 4]), &mut done).unwrap());
        assert!(done.is_empty());
    }

    #[test]
    fn netlink_errors_and_truncation_are_reported() {
        let error = message(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            parse_messages(&error, &mut Vec::new())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        let mut truncated = message(RTM_NEWROUTE, &rtmsg(libc::AF_INET as u8, 8, RTN_UNICAST));
        truncated[0] = 200;
        assert!(parse_messages(&truncated, &mut Vec::new()).is_err());
        // An attribute longer than its message is ignored, not read past.
        let mut payload = rtmsg(libc::AF_INET as u8, 8, RTN_UNICAST);
        payload.extend_from_slice(&64u16.to_ne_bytes());
        payload.extend_from_slice(&RTA_DST.to_ne_bytes());
        let mut routes = Vec::new();
        parse_messages(&message(RTM_NEWROUTE, &payload), &mut routes).unwrap();
        assert_eq!(routes, vec![route("0.0.0.0/8", &[])]);
    }

    #[test]
    fn the_dump_request_asks_for_every_table() {
        let request = dump_request(libc::AF_INET6 as u8, 7);
        assert_eq!(request.len(), NLMSG_HEADER + RTMSG);
        assert_eq!(u16_at(&request, 4), Some(RTM_GETROUTE));
        assert_eq!(u16_at(&request, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(u32_at(&request, 8), Some(7));
        assert_eq!(request[NLMSG_HEADER], libc::AF_INET6 as u8);
        assert!(request[NLMSG_HEADER + 1..].iter().all(|b| *b == 0));
    }

    #[test]
    fn the_host_tables_can_be_read() {
        // Every Linux host has loopback; the route tables may be empty.
        let links = host_links().expect("interfaces");
        assert!(links.values().any(|link| link.name == "lo"));
        let routes = host_routes().expect("routes");
        assert!(routes
            .iter()
            .all(|route| route.destination == route.destination.trunc()));
    }
}
