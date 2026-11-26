//! What the host already reaches without the mesh, for the overlap rule of
//! spec §15.4 (Linux).
//!
//! An accepted subnet is kept out of the system routes and out of the mesh's
//! destination lookup when it overlaps one of:
//!
//! - the address networks of every interface but loopback and our own mesh
//!   interfaces (a physical LAN, or an address on another mesh program's
//!   virtual interface), read by the caller;
//! - the routes of [`foreign_routes`]: routes that leave through another
//!   program's virtual interface (point-to-point, without a link layer, or a
//!   TUN/TAP device), and blackhole, unreachable and prohibit routes, from
//!   every routing table, each kept only when the system actually selects
//!   it: a lookup of its destination (`RTM_F_FIB_MATCH`, so policy rules
//!   and `throw` routes apply) leaves through such an interface, or is
//!   refused. Routes wider than /8 (IPv4) or /7 (IPv6) are left out: they
//!   are default routes or their splits (0.0.0.0/1 + 128.0.0.0/1 and
//!   finer), and would otherwise turn every advertisement local while that
//!   program carries the default route.
//!
//! Our own mesh interfaces never count, whichever network they belong to:
//! otherwise a route we install would be found on the next scan, withdrawn as
//! an overlap, and installed again once gone. They are recognised by the
//! interface index recorded when this process starts serving them
//! ([`claim_own_interface`]), not by their name.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use outbound_mesh::IpNet;

/// Names our mesh interfaces start with: `anixmesh0` for `run`,
/// `anixmesh-<n>` for the managed networks.
pub const OWN_INTERFACE_PREFIX: &str = "anixmesh";

/// Narrowest prefix that still counts as a default-route split.
const WIDEST_V4: u8 = 8;
const WIDEST_V6: u8 = 7;

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
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;
const RTM_F_FIB_MATCH: u32 = 0x2000;
const RTN_UNICAST: u8 = 1;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_MULTIPATH: u16 = 9;

/// Dumps started again when the tables change while being read.
const DUMP_ATTEMPTS: usize = 3;
/// Route lookups made per scan at most.
const MAX_LOOKUPS: usize = 1024;
/// How long one netlink read may wait.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Indexes of the mesh interfaces this process serves.
static OWN_INDEXES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

/// Records one of our mesh interfaces for as long as it is held.
#[derive(Debug)]
pub struct OwnInterface(u32);

impl Drop for OwnInterface {
    fn drop(&mut self) {
        let mut own = OWN_INDEXES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = own.iter().position(|index| *index == self.0) {
            own.swap_remove(at);
        }
    }
}

/// The index of interface `name`.
pub fn interface_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: `name` is a valid C string for the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// Records `name` as one of our mesh interfaces until the result is dropped.
pub fn claim_own_interface(name: &str) -> io::Result<OwnInterface> {
    let index = interface_index(name).ok_or_else(io::Error::last_os_error)?;
    OWN_INDEXES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(index);
    Ok(OwnInterface(index))
}

/// Whether interface `index` is one of our mesh interfaces.
pub fn is_own_index(index: u32) -> bool {
    OWN_INDEXES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&index)
}

/// Whether `name` is one of our mesh interfaces: recorded by index, or in
/// `extra` (the interface of the network being served, in case recording
/// it failed).
pub fn is_own_interface(name: &str, extra: &[&str]) -> bool {
    extra.contains(&name) || interface_index(name).is_some_and(is_own_index)
}

/// One route: destination, type and the interfaces it leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    pub destination: IpNet,
    pub kind: u8,
    pub interfaces: Vec<u32>,
}

/// One interface: name and whether it is virtual (point-to-point, without
/// a link layer, or a TUN/TAP device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLink {
    pub name: String,
    pub is_virtual: bool,
}

/// What a lookup of one address found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A route, with the interfaces it leaves through.
    Route(Vec<u32>),
    /// A blackhole, unreachable or prohibit route refuses it.
    Refused,
    /// No route, or nothing known.
    Unknown,
}

fn wide_enough(net: &IpNet) -> bool {
    let widest = match net.network() {
        IpAddr::V4(_) => WIDEST_V4,
        IpAddr::V6(_) => WIDEST_V6,
    };
    net.prefix() >= widest
}

fn is_refusing(kind: u8) -> bool {
    matches!(kind, RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT)
}

/// The routes, at least /8 (IPv4) or /7 (IPv6), that another program's
/// virtual interface carries or that refuse traffic, kept only when
/// `lookup` of their destination shows the system selects them. `own` tells
/// our mesh interfaces by index.
pub fn select_foreign(
    routes: &[HostRoute],
    links: &HashMap<u32, HostLink>,
    own: &dyn Fn(u32) -> bool,
    lookup: &mut dyn FnMut(IpAddr) -> Lookup,
) -> Vec<IpNet> {
    let foreign =
        |index: &u32| !own(*index) && links.get(index).is_some_and(|link| link.is_virtual);
    let mut found: Vec<IpNet> = Vec::new();
    let mut lookups = 0;
    for route in routes
        .iter()
        .filter(|route| wide_enough(&route.destination))
    {
        let candidate = if route.kind == RTN_UNICAST {
            route.interfaces.iter().any(foreign)
        } else {
            is_refusing(route.kind)
        };
        if !candidate || found.contains(&route.destination) {
            continue;
        }
        if lookups == MAX_LOOKUPS {
            break;
        }
        lookups += 1;
        let selected = match lookup(route.destination.network()) {
            Lookup::Route(interfaces) => {
                route.kind == RTN_UNICAST && interfaces.iter().any(foreign)
            }
            Lookup::Refused => is_refusing(route.kind),
            Lookup::Unknown => false,
        };
        if selected {
            found.push(route.destination);
        }
    }
    found.sort_by_key(|net| net.to_string());
    found
}

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
/// that are neither unicast nor refusing, or carry no destination of a
/// known family.
fn parse_route(payload: &[u8]) -> Option<HostRoute> {
    let header = payload.get(..RTMSG)?;
    let family = libc::c_int::from(header[0]);
    let prefix = header[1];
    let kind = header[7];
    if kind != RTN_UNICAST && !is_refusing(kind) {
        return None;
    }
    let mut destination = None;
    let mut interfaces = Vec::new();
    for (attribute, value) in attributes(&payload[RTMSG..]) {
        match attribute {
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
        kind,
        interfaces,
    })
}

/// Where reading a dump stands after one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    More,
    Done,
    /// Finished, but the tables changed while they were read
    /// (`NLM_F_DUMP_INTR`): the dump must start again.
    Interrupted,
}

/// Splits a buffer of netlink messages answering request `sequence`;
/// messages of other requests are skipped. A netlink error message becomes
/// an error. `interrupted` records `NLM_F_DUMP_INTR` on any message.
fn parse_messages(
    mut bytes: &[u8],
    sequence: u32,
    routes: &mut Vec<HostRoute>,
    interrupted: &mut bool,
) -> io::Result<Progress> {
    while bytes.len() >= NLMSG_HEADER {
        let length = u32_at(bytes, 0).unwrap_or(0) as usize;
        let kind = u16_at(bytes, 4).unwrap_or(0);
        let flags = u16_at(bytes, 6).unwrap_or(0);
        let answers = u32_at(bytes, 8).unwrap_or(0);
        if length < NLMSG_HEADER || length > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a truncated routing message",
            ));
        }
        let payload = &bytes[NLMSG_HEADER..length];
        bytes = &bytes[align(length).min(bytes.len())..];
        if answers != sequence {
            continue;
        }
        if flags & NLM_F_DUMP_INTR != 0 {
            *interrupted = true;
        }
        match kind {
            NLMSG_DONE => {
                return Ok(if *interrupted {
                    Progress::Interrupted
                } else {
                    Progress::Done
                });
            }
            NLMSG_ERROR => {
                let code = u32_at(payload, 0).unwrap_or(0) as i32;
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
            RTM_NEWROUTE => routes.extend(parse_route(payload)),
            _ => {}
        }
    }
    Ok(Progress::More)
}

fn next_sequence() -> u32 {
    NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn header(length: usize, flags: u16, sequence: u32) -> Vec<u8> {
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(&(length as u32).to_ne_bytes());
    request.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request
}

/// The request for a dump of every routing table of `family`.
fn dump_request(family: u8, sequence: u32) -> Vec<u8> {
    let mut request = header(NLMSG_HEADER + RTMSG, NLM_F_REQUEST | NLM_F_DUMP, sequence);
    // rtmsg: family, then zeros (every table, every type).
    request.push(family);
    request.extend_from_slice(&[0u8; RTMSG - 1]);
    request
}

/// The request for the route the system selects for `address`, as the
/// routing table entry that matched (`RTM_F_FIB_MATCH`).
fn lookup_request(address: IpAddr, sequence: u32) -> Vec<u8> {
    let (family, bits, octets): (u8, u8, Vec<u8>) = match address {
        IpAddr::V4(v4) => (libc::AF_INET as u8, 32, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, 128, v6.octets().to_vec()),
    };
    let attribute = 4 + octets.len();
    let mut request = header(NLMSG_HEADER + RTMSG + attribute, NLM_F_REQUEST, sequence);
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type,
    // flags.
    request.extend_from_slice(&[family, bits, 0, 0, 0, 0, 0, 0]);
    request.extend_from_slice(&RTM_F_FIB_MATCH.to_ne_bytes());
    request.extend_from_slice(&(attribute as u16).to_ne_bytes());
    request.extend_from_slice(&RTA_DST.to_ne_bytes());
    request.extend_from_slice(&octets);
    request
}

/// A netlink route socket whose reads give up after [`RECEIVE_TIMEOUT`].
fn route_socket() -> io::Result<OwnedFd> {
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
    let timeout = libc::timeval {
        tv_sec: RECEIVE_TIMEOUT.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: the option value is a valid timeval for its size.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn send(socket: &OwnedFd, request: &[u8]) -> io::Result<()> {
    // SAFETY: the request buffer is valid for its length; the kernel is the
    // default destination of an unbound netlink socket.
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
    Ok(())
}

fn receive<'a>(socket: &OwnedFd, buffer: &'a mut [u8]) -> io::Result<&'a [u8]> {
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
        if received >= 0 {
            return Ok(&buffer[..received as usize]);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Every unicast and refusing route of every table of `family`, started
/// again while the tables change underneath.
fn dump(socket: &OwnedFd, family: libc::c_int, buffer: &mut [u8]) -> io::Result<Vec<HostRoute>> {
    for _ in 0..DUMP_ATTEMPTS {
        let sequence = next_sequence();
        send(socket, &dump_request(family as u8, sequence))?;
        let mut routes = Vec::new();
        let mut interrupted = false;
        let progress = loop {
            let bytes = receive(socket, buffer)?;
            if bytes.is_empty() {
                break Progress::Done;
            }
            match parse_messages(bytes, sequence, &mut routes, &mut interrupted) {
                Ok(Progress::More) => {}
                Ok(progress) => break progress,
                // A host without IPv6 answers the IPv6 dump with an error.
                Err(error)
                    if family == libc::AF_INET6
                        && error.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
                {
                    return Ok(Vec::new());
                }
                Err(error) => return Err(error),
            }
        };
        if progress == Progress::Done {
            return Ok(routes);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "the routing tables kept changing while they were read",
    ))
}

/// The answer to lookup `sequence` in `bytes`, if it is there: the type of
/// the route that matched, or the error the kernel gives for a blackhole,
/// unreachable or prohibit route.
fn parse_lookup(mut bytes: &[u8], sequence: u32) -> io::Result<Option<Lookup>> {
    while bytes.len() >= NLMSG_HEADER {
        let length = u32_at(bytes, 0).unwrap_or(0) as usize;
        let kind = u16_at(bytes, 4).unwrap_or(0);
        let answers = u32_at(bytes, 8).unwrap_or(0);
        if length < NLMSG_HEADER || length > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a truncated routing message",
            ));
        }
        let payload = &bytes[NLMSG_HEADER..length];
        bytes = &bytes[align(length).min(bytes.len())..];
        if answers != sequence {
            continue;
        }
        match kind {
            RTM_NEWROUTE => {
                return Ok(Some(match parse_route(payload) {
                    Some(route) if route.kind == RTN_UNICAST => Lookup::Route(route.interfaces),
                    Some(_) => Lookup::Refused,
                    // A local, broadcast or other route: not another
                    // program's.
                    None => Lookup::Unknown,
                }));
            }
            NLMSG_ERROR => {
                let code = -(u32_at(payload, 0).unwrap_or(0) as i32);
                return match code {
                    libc::EINVAL | libc::EHOSTUNREACH | libc::EACCES => Ok(Some(Lookup::Refused)),
                    0 | libc::ENETUNREACH => Ok(Some(Lookup::Unknown)),
                    code => Err(io::Error::from_raw_os_error(code)),
                };
            }
            _ => {}
        }
    }
    Ok(None)
}

/// The route the system selects for `address`.
fn lookup(socket: &OwnedFd, address: IpAddr, buffer: &mut [u8]) -> io::Result<Lookup> {
    let sequence = next_sequence();
    send(socket, &lookup_request(address, sequence))?;
    loop {
        let bytes = receive(socket, buffer)?;
        if bytes.is_empty() {
            return Ok(Lookup::Unknown);
        }
        if let Some(found) = parse_lookup(bytes, sequence)? {
            return Ok(found);
        }
    }
}

/// Every route of every table, IPv4 and IPv6.
pub fn host_routes() -> io::Result<Vec<HostRoute>> {
    let socket = route_socket()?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut routes = dump(&socket, libc::AF_INET, &mut buffer)?;
    routes.extend(dump(&socket, libc::AF_INET6, &mut buffer)?);
    Ok(routes)
}

/// The routes of other programs' virtual interfaces and the refusing
/// routes that the system selects (see the module documentation). `own`
/// names the interface being served, in addition to those recorded.
pub fn foreign_routes(own: &str) -> io::Result<Vec<IpNet>> {
    let links = host_links()?;
    let socket = route_socket()?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut routes = dump(&socket, libc::AF_INET, &mut buffer)?;
    routes.extend(dump(&socket, libc::AF_INET6, &mut buffer)?);
    let named = interface_index(own);
    let is_own = |index: u32| is_own_index(index) || named == Some(index);
    let mut failed = None;
    let found = select_foreign(&routes, &links, &is_own, &mut |address| match lookup(
        &socket,
        address,
        &mut buffer,
    ) {
        Ok(found) => found,
        Err(error) => {
            failed.get_or_insert(error);
            Lookup::Unknown
        }
    });
    match failed {
        Some(error) => Err(error),
        None => Ok(found),
    }
}

/// Link type and flags as the kernel shows them under `/sys/class/net`.
fn link_is_virtual(name: &str) -> bool {
    let path = |file: &str| format!("/sys/class/net/{name}/{file}");
    let read = |file: &str| std::fs::read_to_string(path(file));
    let link_type = read("type")
        .ok()
        .and_then(|text| text.trim().parse::<u16>().ok());
    let flags = read("flags")
        .ok()
        .and_then(|text| u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok());
    // TUN and TAP devices alike carry `tun_flags`; a TAP device has an
    // Ethernet link layer, so the link type alone misses it.
    let tun_or_tap = std::path::Path::new(&path("tun_flags")).exists();
    tun_or_tap
        || link_type == Some(ARPHRD_NONE)
        || flags.is_some_and(|flags| flags & IFF_POINTOPOINT != 0)
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

    fn links() -> HashMap<u32, HostLink> {
        let link = |name: &str, is_virtual| HostLink {
            name: name.into(),
            is_virtual,
        };
        HashMap::from([
            (1, link("lo", false)),
            (2, link("eth0", false)),
            (3, link("vpn0", true)),
            (4, link("anixmesh-0", true)),
            (5, link("anixmesh0", true)),
            (6, link("custom9", true)),
        ])
    }

    fn route(text: &str, interfaces: &[u32]) -> HostRoute {
        HostRoute {
            destination: net(text),
            kind: RTN_UNICAST,
            interfaces: interfaces.to_vec(),
        }
    }

    fn refusing(text: &str, kind: u8) -> HostRoute {
        HostRoute {
            destination: net(text),
            kind,
            interfaces: Vec::new(),
        }
    }

    /// Ours: the interfaces at 4 and 5, and `extra`.
    fn ours(extra: &'static [u32]) -> impl Fn(u32) -> bool {
        move |index| index == 4 || index == 5 || extra.contains(&index)
    }

    /// Every lookup finds the route that was asked about.
    fn selected(routes: &[HostRoute]) -> impl FnMut(IpAddr) -> Lookup + '_ {
        move |address| {
            routes
                .iter()
                .filter(|route| route.destination.contains(address))
                .max_by_key(|route| route.destination.prefix())
                .map_or(Lookup::Unknown, |route| {
                    if route.kind == RTN_UNICAST {
                        Lookup::Route(route.interfaces.clone())
                    } else {
                        Lookup::Refused
                    }
                })
        }
    }

    fn foreign(routes: &[HostRoute], own: &dyn Fn(u32) -> bool) -> Vec<IpNet> {
        select_foreign(routes, &links(), own, &mut selected(routes))
    }

    #[test]
    fn only_routes_of_other_virtual_interfaces_count() {
        let routes = [
            route("100.64.0.0/10", &[3]),
            route("192.168.1.0/24", &[2]),
            route("10.20.0.0/16", &[4]),
            route("10.21.0.0/16", &[5]),
            route("10.22.0.0/16", &[6]),
            route("10.23.0.0/16", &[9]),
            route("fd7a:115c:a1e0::/48", &[3]),
        ];
        assert_eq!(
            foreign(&routes, &ours(&[6])),
            vec![net("100.64.0.0/10"), net("fd7a:115c:a1e0::/48")]
        );
        // Without `custom9` as ours, its route counts.
        assert!(foreign(&routes, &ours(&[])).contains(&net("10.22.0.0/16")));
    }

    #[test]
    fn default_routes_and_their_splits_do_not_count() {
        let routes = [
            route("0.0.0.0/0", &[3]),
            route("0.0.0.0/1", &[3]),
            route("128.0.0.0/1", &[3]),
            route("64.0.0.0/2", &[3]),
            route("8.0.0.0/7", &[3]),
            route("10.0.0.0/8", &[3]),
            route("::/0", &[3]),
            route("::/1", &[3]),
            route("8000::/1", &[3]),
            route("fe00::/6", &[3]),
            route("fc00::/7", &[3]),
        ];
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |_| {
            Lookup::Route(vec![3])
        });
        assert_eq!(found, vec![net("10.0.0.0/8"), net("fc00::/7")]);
    }

    #[test]
    fn a_multipath_route_counts_when_any_hop_is_foreign() {
        let routes = [
            route("10.30.0.0/16", &[2, 3]),
            route("10.31.0.0/16", &[2, 4]),
        ];
        assert_eq!(foreign(&routes, &ours(&[])), vec![net("10.30.0.0/16")]);
    }

    #[test]
    fn only_routes_the_system_selects_count() {
        let routes = [
            route("100.64.0.0/10", &[3]),
            route("10.40.0.0/16", &[3]),
            refusing("10.50.0.0/16", RTN_BLACKHOLE),
            refusing("10.51.0.0/16", RTN_UNREACHABLE),
            refusing("10.52.0.0/16", RTN_PROHIBIT),
            refusing("10.0.0.0/7", RTN_BLACKHOLE),
            // A throw route only sends the lookup on to the next table.
            refusing("10.53.0.0/16", 9),
        ];
        // The policy rules send 10.40.0.0/16 out through eth0 (a table of
        // another program is not consulted), and 10.51.0.0/16 is reached
        // through another, preferred table.
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |address| match address
            .to_string()
            .as_str()
        {
            "10.40.0.0" => Lookup::Route(vec![2]),
            "10.51.0.0" => Lookup::Route(vec![2]),
            "100.64.0.0" => Lookup::Route(vec![3]),
            _ => Lookup::Refused,
        });
        assert_eq!(
            found,
            vec![
                net("10.50.0.0/16"),
                net("10.52.0.0/16"),
                net("100.64.0.0/10")
            ]
        );
        // A route that leaves through our own interface in the end is ours.
        let found = select_foreign(&routes[..1], &links(), &ours(&[]), &mut |_| {
            Lookup::Route(vec![4])
        });
        assert!(found.is_empty());
        // Nothing known: nothing counts.
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |_| Lookup::Unknown);
        assert!(found.is_empty());
    }

    #[test]
    fn own_interfaces_are_recognised_by_index_or_name() {
        assert!(is_own_interface("custom9", &["custom9"]));
        assert!(!is_own_interface("vpn0", &["custom9"]));
        // A name like ours is not enough.
        assert!(!is_own_interface("anixmesh-missing", &[]));
        let lo = interface_index("lo").expect("loopback");
        assert!(!is_own_index(lo));
        let claim = claim_own_interface("lo").expect("claim");
        assert!(is_own_index(lo));
        assert!(is_own_interface("lo", &[]));
        drop(claim);
        assert!(!is_own_index(lo));
        assert!(claim_own_interface("anixmesh-missing").is_err());
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    const SEQUENCE: u32 = 41;

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        message_with(kind, 0, SEQUENCE, payload)
    }

    fn message_with(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((NLMSG_HEADER + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(payload);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn parse(bytes: &[u8], routes: &mut Vec<HostRoute>) -> io::Result<Progress> {
        parse_messages(bytes, SEQUENCE, routes, &mut false)
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

        // A local route (type 2) is skipped; a blackhole is kept.
        let mut local = rtmsg(libc::AF_INET as u8, 32, 2);
        local.extend(attribute(RTA_DST, &[127, 0, 0, 1]));
        let mut blackhole = rtmsg(libc::AF_INET as u8, 16, RTN_BLACKHOLE);
        blackhole.extend(attribute(RTA_DST, &[10, 50, 0, 0]));

        let mut bytes = Vec::new();
        for payload in [&ipv4, &ipv6, &default, &local, &blackhole] {
            bytes.extend(message(RTM_NEWROUTE, payload));
        }
        // An answer to another request is skipped.
        bytes.extend(message_with(RTM_NEWROUTE, 0, SEQUENCE + 1, &ipv4));
        let mut routes = Vec::new();
        assert_eq!(parse(&bytes, &mut routes).unwrap(), Progress::More);
        assert_eq!(
            routes,
            vec![
                route("100.64.0.0/10", &[3]),
                route("fd7a:115c:a1e0::/48", &[2, 3]),
                route("0.0.0.0/0", &[2]),
                refusing("10.50.0.0/16", RTN_BLACKHOLE),
            ]
        );

        let mut done = Vec::new();
        assert_eq!(
            parse(&message(NLMSG_DONE, &[0u8; 4]), &mut done).unwrap(),
            Progress::Done
        );
        assert!(done.is_empty());
        // The DONE of another request does not end this one.
        let other = message_with(NLMSG_DONE, 0, SEQUENCE + 1, &[0u8; 4]);
        assert_eq!(parse(&other, &mut done).unwrap(), Progress::More);
    }

    #[test]
    fn a_dump_the_tables_changed_under_is_marked_interrupted() {
        let mut payload = rtmsg(libc::AF_INET as u8, 10, RTN_UNICAST);
        payload.extend(attribute(RTA_DST, &[100, 64, 0, 0]));
        let mut bytes = message_with(RTM_NEWROUTE, NLM_F_DUMP_INTR, SEQUENCE, &payload);
        bytes.extend(message(NLMSG_DONE, &[0u8; 4]));
        let mut interrupted = false;
        let progress = parse_messages(&bytes, SEQUENCE, &mut Vec::new(), &mut interrupted).unwrap();
        assert_eq!(progress, Progress::Interrupted);
        assert!(interrupted);
    }

    #[test]
    fn netlink_errors_and_truncation_are_reported() {
        let error = message(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            parse(&error, &mut Vec::new()).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        let mut truncated = message(RTM_NEWROUTE, &rtmsg(libc::AF_INET as u8, 8, RTN_UNICAST));
        truncated[0] = 200;
        assert!(parse(&truncated, &mut Vec::new()).is_err());
        // An attribute longer than its message is ignored, not read past.
        let mut payload = rtmsg(libc::AF_INET as u8, 8, RTN_UNICAST);
        payload.extend_from_slice(&64u16.to_ne_bytes());
        payload.extend_from_slice(&RTA_DST.to_ne_bytes());
        let mut routes = Vec::new();
        parse(&message(RTM_NEWROUTE, &payload), &mut routes).unwrap();
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
    fn lookup_answers_are_read() {
        let mut unicast = rtmsg(libc::AF_INET as u8, 16, RTN_UNICAST);
        unicast.extend(attribute(RTA_DST, &[10, 40, 0, 0]));
        unicast.extend(attribute(RTA_OIF, &3u32.to_ne_bytes()));
        let answer = message(RTM_NEWROUTE, &unicast);
        assert_eq!(
            parse_lookup(&answer, SEQUENCE).unwrap(),
            Some(Lookup::Route(vec![3]))
        );
        // An answer to another request is not this one's.
        assert_eq!(parse_lookup(&answer, SEQUENCE + 1).unwrap(), None);
        let local = message(RTM_NEWROUTE, &rtmsg(libc::AF_INET as u8, 8, 2));
        assert_eq!(
            parse_lookup(&local, SEQUENCE).unwrap(),
            Some(Lookup::Unknown)
        );
        for (code, found) in [
            (libc::EINVAL, Some(Lookup::Refused)),
            (libc::EHOSTUNREACH, Some(Lookup::Refused)),
            (libc::EACCES, Some(Lookup::Refused)),
            (libc::ENETUNREACH, Some(Lookup::Unknown)),
        ] {
            let error = message(NLMSG_ERROR, &(-code).to_ne_bytes());
            assert_eq!(parse_lookup(&error, SEQUENCE).unwrap(), found);
        }
        let error = message(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        assert!(parse_lookup(&error, SEQUENCE).is_err());
    }

    #[test]
    fn the_lookup_request_asks_for_the_matching_entry() {
        let request = lookup_request("10.40.0.0".parse().unwrap(), 9);
        assert_eq!(request.len(), NLMSG_HEADER + RTMSG + 8);
        assert_eq!(u32_at(&request, 0), Some(request.len() as u32));
        assert_eq!(u16_at(&request, 6), Some(NLM_F_REQUEST));
        assert_eq!(u32_at(&request, 8), Some(9));
        assert_eq!(request[NLMSG_HEADER], libc::AF_INET as u8);
        assert_eq!(request[NLMSG_HEADER + 1], 32);
        assert_eq!(u32_at(&request, NLMSG_HEADER + 8), Some(RTM_F_FIB_MATCH));
        assert_eq!(
            attributes(&request[NLMSG_HEADER + RTMSG..]),
            vec![(RTA_DST, &[10u8, 40, 0, 0][..])]
        );
        let request = lookup_request("fd00::1".parse().unwrap(), 9);
        assert_eq!(request.len(), NLMSG_HEADER + RTMSG + 20);
        assert_eq!(request[NLMSG_HEADER + 1], 128);
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
        // The lookup request is understood: loopback is found on `lo`.
        let socket = route_socket().expect("socket");
        let mut buffer = vec![0u8; 64 * 1024];
        // Loopback matches a local route, which is nobody's mesh.
        let found = lookup(&socket, IpAddr::V4(Ipv4Addr::LOCALHOST), &mut buffer);
        assert!(matches!(found, Ok(Lookup::Unknown)), "{found:?}");
        foreign_routes("lo").expect("foreign routes");
    }
}
