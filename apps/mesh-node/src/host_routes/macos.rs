//! macOS side of [`super`]: routes from a routing socket dump
//! (`sysctl` `NET_RT_DUMP`), interfaces from `getifaddrs`.
//!
//! macOS has no policy routing tables like Linux, but scoped routes
//! (`RTF_IFSCOPE`) are kept per interface in the same table and come with
//! the dump, so routes another program binds to its own interface are seen.

use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use outbound_mesh::IpNet;

use super::{HostLink, HostRoute};

/// Length of `struct rt_msghdr`, after which the socket addresses follow.
const RT_MSGHDR: usize = std::mem::size_of::<libc::rt_msghdr>();

/// Routes the kernel makes by itself for neighbours (ARP and ND entries) and
/// clones of other routes; they are not routes another program installed.
const NOT_INSTALLED: libc::c_int = libc::RTF_LLINFO | libc::RTF_WASCLONED;

/// Socket addresses in routing messages are padded to 4 bytes; a zero length
/// still takes 4.
fn padded(length: usize) -> usize {
    if length == 0 {
        4
    } else {
        (length + 3) & !3
    }
}

/// The address bytes of a socket address of `family`, as many as its
/// length covers (masks are cut after their last non-zero byte), padded with
/// zeros.
fn address_bytes<const N: usize>(sockaddr: &[u8], offset: usize) -> [u8; N] {
    let mut bytes = [0u8; N];
    let length = usize::from(sockaddr.first().copied().unwrap_or(0)).min(sockaddr.len());
    if length > offset {
        let available = (length - offset).min(N);
        bytes[..available].copy_from_slice(&sockaddr[offset..offset + available]);
    }
    bytes
}

fn ones(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for byte in bytes {
        // A mask is contiguous; stop at the first gap.
        let leading = byte.leading_ones() as u8;
        count += leading;
        if leading < 8 {
            break;
        }
    }
    count
}

/// One routing message of the dump: header, then the socket addresses its
/// `rtm_addrs` bits name, in bit order. `None` for messages that are not a
/// unicast route of IPv4 or IPv6.
fn parse_route(message: &[u8]) -> Option<HostRoute> {
    if message.len() < RT_MSGHDR {
        return None;
    }
    // SAFETY: the buffer holds a whole header; it is read unaligned.
    let header: libc::rt_msghdr =
        unsafe { std::ptr::read_unaligned(message.as_ptr().cast::<libc::rt_msghdr>()) };
    if header.rtm_flags & NOT_INSTALLED != 0 || header.rtm_flags & libc::RTF_UP == 0 {
        return None;
    }
    let mut sockaddrs: [Option<&[u8]>; 8] = [None; 8];
    let mut at = RT_MSGHDR;
    for (bit, slot) in sockaddrs.iter_mut().enumerate() {
        if header.rtm_addrs & (1 << bit) == 0 {
            continue;
        }
        let length = usize::from(*message.get(at)?);
        let end = (at + length).min(message.len());
        *slot = Some(&message[at..end]);
        at += padded(length);
    }
    let destination = sockaddrs[libc::RTAX_DST as usize]?;
    let family = libc::c_int::from(*destination.get(1)?);
    let mask = sockaddrs[libc::RTAX_NETMASK as usize];
    let host = header.rtm_flags & libc::RTF_HOST != 0;
    let (address, prefix) = match family {
        libc::AF_INET => {
            let address = IpAddr::V4(Ipv4Addr::from(address_bytes::<4>(destination, 4)));
            let prefix = match mask {
                _ if host => 32,
                Some(mask) => ones(&address_bytes::<4>(mask, 4)),
                None => 32,
            };
            (address, prefix)
        }
        libc::AF_INET6 => {
            let mut bytes = address_bytes::<16>(destination, 8);
            // Link-local and interface-local addresses carry the scope in
            // bytes 2 and 3 inside the kernel; clear it.
            if (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80) || bytes[0] == 0xff {
                bytes[2] = 0;
                bytes[3] = 0;
            }
            let address = IpAddr::V6(Ipv6Addr::from(bytes));
            let prefix = match mask {
                _ if host => 128,
                Some(mask) => ones(&address_bytes::<16>(mask, 8)),
                None => 128,
            };
            (address, prefix)
        }
        _ => return None,
    };
    Some(HostRoute {
        destination: IpNet::new(address, prefix)?.trunc(),
        interfaces: vec![u32::from(header.rtm_index)],
    })
}

/// Splits a dump into its messages and keeps the routes.
fn parse_dump(mut bytes: &[u8]) -> Vec<HostRoute> {
    let mut routes = Vec::new();
    while bytes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            break;
        }
        // Only messages of the version this layout describes.
        if bytes[2] == libc::RTM_VERSION as u8 {
            routes.extend(parse_route(&bytes[..length]));
        }
        bytes = &bytes[length..];
    }
    routes
}

/// Every unicast route of the table, IPv4 and IPv6, scoped routes included.
pub fn host_routes() -> io::Result<Vec<HostRoute>> {
    let mut name = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    // The table can grow between the size query and the read; try again a
    // few times with the new size.
    for _ in 0..4 {
        let mut size: libc::size_t = 0;
        // SAFETY: a size query with a null buffer.
        let result = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; size + size / 4 + 1024];
        let mut length = buffer.len();
        // SAFETY: the buffer is valid for writes of `length` bytes.
        let result = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as libc::c_uint,
                buffer.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            return Ok(parse_dump(&buffer[..length.min(buffer.len())]));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("the routing table kept growing"))
}

/// Every interface by index. Virtual means point-to-point, as the `utun`,
/// `ipsec` and `ppp` interfaces other programs use are.
pub fn host_links() -> io::Result<HashMap<u32, HostLink>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `head` with a list freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut links = HashMap::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` points into the list `getifaddrs` returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a non-null name is a C string.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let Ok(c_name) = std::ffi::CString::new(name.as_str()) else {
            continue;
        };
        // SAFETY: a valid C string.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            continue;
        }
        let is_virtual = entry.ifa_flags & (libc::IFF_POINTOPOINT as libc::c_uint) != 0;
        links
            .entry(index)
            .and_modify(|link: &mut HostLink| link.is_virtual |= is_virtual)
            .or_insert(HostLink { name, is_virtual });
    }
    // SAFETY: `head` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn sockaddr_in(address: [u8; 4], length: u8) -> Vec<u8> {
        let mut bytes = vec![length, libc::AF_INET as u8, 0, 0];
        bytes.extend_from_slice(&address);
        bytes.resize(usize::from(length).max(8), 0);
        bytes.truncate(usize::from(length));
        bytes
    }

    fn sockaddr_in6(address: [u8; 16]) -> Vec<u8> {
        let mut bytes = vec![28, libc::AF_INET6 as u8, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }

    fn message(flags: libc::c_int, index: u16, addrs: &[(libc::c_int, Vec<u8>)]) -> Vec<u8> {
        // SAFETY: an all-zero header is valid.
        let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        header.rtm_version = libc::RTM_VERSION as u8;
        header.rtm_type = libc::RTM_GET as u8;
        header.rtm_flags = flags;
        header.rtm_index = index;
        let mut body = Vec::new();
        for (bit, sockaddr) in addrs {
            header.rtm_addrs |= bit;
            body.extend_from_slice(sockaddr);
            body.resize(body.len() - sockaddr.len() + padded(sockaddr.len()), 0);
        }
        header.rtm_msglen = (RT_MSGHDR + body.len()) as u16;
        // SAFETY: the header is plain data.
        let mut bytes = unsafe {
            std::slice::from_raw_parts((&header as *const libc::rt_msghdr).cast::<u8>(), RT_MSGHDR)
        }
        .to_vec();
        bytes.extend(body);
        bytes
    }

    #[test]
    fn routes_and_masks_are_read() {
        let up = libc::RTF_UP | libc::RTF_STATIC;
        let mut dump = message(
            up,
            7,
            &[
                (libc::RTA_DST, sockaddr_in([100, 64, 0, 0], 16)),
                (libc::RTA_GATEWAY, sockaddr_in([100, 64, 0, 1], 16)),
                // A mask cut after its last non-zero byte.
                (libc::RTA_NETMASK, sockaddr_in([255, 192, 0, 0], 6)),
            ],
        );
        dump.extend(message(
            up | libc::RTF_HOST,
            7,
            &[(libc::RTA_DST, sockaddr_in([10, 9, 8, 7], 16))],
        ));
        // A default route: the mask has no address bytes at all.
        dump.extend(message(
            up,
            4,
            &[
                (libc::RTA_DST, sockaddr_in([0, 0, 0, 0], 16)),
                (libc::RTA_NETMASK, sockaddr_in([0, 0, 0, 0], 0)),
            ],
        ));
        let mut v6 = [0u8; 16];
        v6[..6].copy_from_slice(&[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]);
        let mut mask = [0u8; 16];
        mask[..6].fill(0xff);
        dump.extend(message(
            up,
            7,
            &[
                (libc::RTA_DST, sockaddr_in6(v6)),
                (libc::RTA_NETMASK, sockaddr_in6(mask)),
            ],
        ));
        // Neighbour entries and clones are left out.
        dump.extend(message(
            up | libc::RTF_LLINFO,
            4,
            &[(libc::RTA_DST, sockaddr_in([192, 168, 1, 1], 16))],
        ));
        dump.extend(message(
            up | libc::RTF_WASCLONED,
            4,
            &[(libc::RTA_DST, sockaddr_in([192, 168, 1, 2], 16))],
        ));
        let routes = parse_dump(&dump);
        let found: Vec<(String, Vec<u32>)> = routes
            .iter()
            .map(|route| (route.destination.to_string(), route.interfaces.clone()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("100.64.0.0/10".to_string(), vec![7]),
                ("10.9.8.7/32".to_string(), vec![7]),
                ("0.0.0.0/0".to_string(), vec![4]),
                ("fd7a:115c:a1e0::/48".to_string(), vec![7]),
            ]
        );
        assert_eq!(routes[0].destination, net("100.64.0.0/10"));
    }

    #[test]
    fn a_truncated_dump_stops_cleanly() {
        let dump = message(
            libc::RTF_UP,
            3,
            &[(libc::RTA_DST, sockaddr_in([10, 0, 0, 0], 16))],
        );
        assert!(parse_dump(&dump[..dump.len() - 3]).is_empty());
        assert!(parse_dump(&[]).is_empty());
    }

    #[test]
    fn the_host_tables_can_be_read() {
        let links = host_links().expect("interfaces");
        assert!(links.values().any(|link| link.name == "lo0"));
        let routes = host_routes().expect("routes");
        assert!(routes
            .iter()
            .all(|route| route.destination == route.destination.trunc()));
        assert!(!routes.is_empty());
    }
}
