//! The macOS virtual interface of `run`: a `utun` interface from the
//! kernel control socket, its addresses and MTU set with the interface
//! ioctls and its routes written to a routing socket, so no `ifconfig` or
//! `route` program runs.
//!
//! macOS names the interface itself (`utunN`); [`Tun::name`] gives the name
//! it chose. Closing the socket removes the interface together with its
//! addresses and routes. Each packet on the socket carries a 4-byte address
//! family in front, which is added and removed here.

use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::io::unix::AsyncFd;

/// Kernel control that creates `utun` interfaces.
const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";

/// `_IOW('i', 26, struct ifaliasreq)`: add an IPv4 address.
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
/// `_IOW('i', 26, struct in6_aliasreq)`: add an IPv6 address.
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080_691a;
/// `_IOW('i', 52, struct ifreq)`: set the MTU.
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;
/// `_IOWR('i', 17, struct ifreq)` / `_IOW('i', 16, struct ifreq)`: flags.
const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911;
const SIOCSIFFLAGS: libc::c_ulong = 0x8020_6910;

/// Lifetime of an address that never expires.
const ND6_INFINITE_LIFETIME: u32 = u32::MAX;

/// The address family word in front of each packet.
const FAMILY_V4: [u8; 4] = (libc::AF_INET as u32).to_be_bytes();
const FAMILY_V6: [u8; 4] = (libc::AF_INET6 as u32).to_be_bytes();

/// `struct ifreq` with the integer member of its union.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    value: libc::c_int,
    _rest: [u8; 12],
}

/// `struct ifaliasreq`.
#[repr(C)]
struct IfAliasReq {
    name: [u8; libc::IFNAMSIZ],
    address: libc::sockaddr_in,
    destination: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

/// `struct in6_addrlifetime`.
#[repr(C)]
#[derive(Default)]
struct In6AddrLifetime {
    expire: libc::time_t,
    preferred: libc::time_t,
    valid_time: u32,
    preferred_time: u32,
}

/// `struct in6_aliasreq`.
#[repr(C)]
struct In6AliasReq {
    name: [u8; libc::IFNAMSIZ],
    address: libc::sockaddr_in6,
    destination: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: libc::c_int,
    lifetime: In6AddrLifetime,
}

fn name_bytes(name: &str) -> io::Result<[u8; libc::IFNAMSIZ]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must be 1 to 15 bytes without NUL",
        ));
    }
    let mut field = [0u8; libc::IFNAMSIZ];
    field[..bytes.len()].copy_from_slice(bytes);
    Ok(field)
}

fn sockaddr_in(address: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: an all-zero `sockaddr_in` is valid.
    let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sockaddr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
    sockaddr.sin_addr.s_addr = u32::from(address).to_be();
    sockaddr
}

fn sockaddr_in6(address: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: an all-zero `sockaddr_in6` is valid.
    let mut sockaddr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sockaddr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sockaddr.sin6_addr.s6_addr = address.octets();
    sockaddr
}

fn ipv4_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(bits)
}

fn ipv6_mask(prefix: u8) -> Ipv6Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix.min(128)))
    };
    Ipv6Addr::from(bits)
}

fn socket(family: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain socket call; the descriptor is owned below.
    let fd = unsafe { libc::socket(family, kind, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ioctl<T>(fd: &OwnedFd, request: libc::c_ulong, argument: &mut T) -> io::Result<()> {
    // SAFETY: `argument` is the structure the request reads and writes.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, std::ptr::from_mut(argument)) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Socket addresses in routing messages, padded to 4 bytes.
fn push_sockaddr(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(bytes);
    let padded = (bytes.len() + 3) & !3;
    message.resize(message.len() + padded - bytes.len(), 0);
}

fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: the socket address structures here are plain data without
    // padding the kernel would misread.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

static ROUTE_SEQUENCE: AtomicI32 = AtomicI32::new(1);

/// One routing message adding or deleting `network`/`prefix` through the
/// interface with `index`.
fn route_message(kind: libc::c_int, index: u16, network: IpAddr, prefix: u8) -> Vec<u8> {
    // SAFETY: an all-zero header is valid.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = kind as u8;
    header.rtm_index = index;
    header.rtm_seq = ROUTE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    header.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
    header.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY;
    let full = match network {
        IpAddr::V4(_) => prefix >= 32,
        IpAddr::V6(_) => prefix >= 128,
    };
    if full {
        header.rtm_flags |= libc::RTF_HOST;
    } else {
        header.rtm_addrs |= libc::RTA_NETMASK;
    }

    let mut body = Vec::new();
    match network {
        IpAddr::V4(address) => push_sockaddr(&mut body, as_bytes(&sockaddr_in(address))),
        IpAddr::V6(address) => push_sockaddr(&mut body, as_bytes(&sockaddr_in6(address))),
    }
    // The gateway is the interface itself, as `route -interface` gives it.
    // SAFETY: an all-zero `sockaddr_dl` is valid.
    let mut link: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
    link.sdl_len = std::mem::size_of::<libc::sockaddr_dl>() as u8;
    link.sdl_family = libc::AF_LINK as u8;
    link.sdl_index = index;
    push_sockaddr(&mut body, as_bytes(&link));
    if !full {
        match network {
            IpAddr::V4(_) => push_sockaddr(&mut body, as_bytes(&sockaddr_in(ipv4_mask(prefix)))),
            IpAddr::V6(_) => push_sockaddr(&mut body, as_bytes(&sockaddr_in6(ipv6_mask(prefix)))),
        }
    }
    let length = std::mem::size_of::<libc::rt_msghdr>() + body.len();
    header.rtm_msglen = length as u16;
    let mut message = as_bytes(&header).to_vec();
    message.extend(body);
    message
}

fn write_route(message: &[u8]) -> io::Result<()> {
    let socket = socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC)?;
    // SAFETY: the message is valid for its length.
    let written =
        unsafe { libc::write(socket.as_raw_fd(), message.as_ptr().cast(), message.len()) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The network of `address`/`prefix`.
fn network_of(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & u32::from(ipv4_mask(prefix)))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
            u128::from(v6) & u128::from(ipv6_mask(prefix)),
        )),
    }
}

/// The `utun` unit for a name like `utun7` (unit 8; 0 lets the kernel
/// choose). Any other name lets the kernel choose.
fn unit_for(name: &str) -> u32 {
    name.strip_prefix("utun")
        .and_then(|number| number.parse::<u32>().ok())
        .and_then(|number| number.checked_add(1))
        .unwrap_or(0)
}

/// An open `utun` interface. Closing it removes the interface.
pub struct Tun {
    socket: AsyncFd<OwnedFd>,
    name: String,
    index: u16,
}

impl Tun {
    /// Creates the interface, gives it `address`/`prefix` (and the IPv6
    /// address if any), sets the MTU, brings it up and routes the virtual
    /// subnets into it (a point-to-point interface gets no subnet route by
    /// itself). `name` is used only when it is a `utunN` name.
    pub fn create(
        name: &str,
        address: (Ipv4Addr, u8),
        address_v6: Option<(Ipv6Addr, u8)>,
        mtu: u16,
    ) -> io::Result<Self> {
        let control = socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)?;
        // SAFETY: an all-zero `ctl_info` is valid.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (target, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL) {
            *target = *byte as libc::c_char;
        }
        ioctl(&control, libc::CTLIOCGINFO, &mut info)?;
        let socket_address = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit_for(name),
            sc_reserved: [0; 5],
        };
        // SAFETY: the address is a valid `sockaddr_ctl` of its length.
        let connected = unsafe {
            libc::connect(
                control.as_raw_fd(),
                std::ptr::from_ref(&socket_address).cast(),
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if connected != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = [0u8; libc::IFNAMSIZ];
        let mut length = buffer.len() as libc::socklen_t;
        // SAFETY: the buffer is valid for `length` bytes.
        let result = unsafe {
            libc::getsockopt(
                control.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                buffer.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let name = CStr::from_bytes_until_nul(&buffer)
            .map_err(|_| io::Error::other("the interface name has no end"))?
            .to_string_lossy()
            .into_owned();
        // SAFETY: plain descriptor flag calls on a descriptor we own.
        unsafe {
            let flags = libc::fcntl(control.as_raw_fd(), libc::F_GETFL);
            if flags < 0
                || libc::fcntl(control.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
                || libc::fcntl(control.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let c_name = std::ffi::CString::new(name.as_str())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: a valid C string.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        let index = u16::try_from(index)
            .ok()
            .filter(|index| *index != 0)
            .ok_or_else(|| io::Error::other("the new interface has no index"))?;

        let field = name_bytes(&name)?;
        let inet = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let mut alias = IfAliasReq {
            name: field,
            address: sockaddr_in(address.0),
            destination: sockaddr_in(address.0),
            mask: sockaddr_in(ipv4_mask(address.1)),
        };
        ioctl(&inet, SIOCAIFADDR, &mut alias)?;
        let mut request = IfReq {
            name: field,
            value: libc::c_int::from(mtu),
            _rest: [0; 12],
        };
        ioctl(&inet, SIOCSIFMTU, &mut request)?;
        let mut request = IfReq {
            name: field,
            value: 0,
            _rest: [0; 12],
        };
        ioctl(&inet, SIOCGIFFLAGS, &mut request)?;
        // `ifr_flags` is a short at the start of the union.
        let flags = request.value as i16 as libc::c_int | libc::IFF_UP | libc::IFF_RUNNING;
        request.value = flags;
        ioctl(&inet, SIOCSIFFLAGS, &mut request)?;
        if let Some((address, prefix)) = address_v6 {
            let inet6 = socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)?;
            let mut alias = In6AliasReq {
                name: field,
                address: sockaddr_in6(address),
                // SAFETY: an all-zero `sockaddr_in6` is valid (no peer).
                destination: unsafe { std::mem::zeroed() },
                mask: sockaddr_in6(ipv6_mask(prefix)),
                flags: 0,
                lifetime: In6AddrLifetime {
                    valid_time: ND6_INFINITE_LIFETIME,
                    preferred_time: ND6_INFINITE_LIFETIME,
                    ..In6AddrLifetime::default()
                },
            };
            ioctl(&inet6, SIOCAIFADDR_IN6, &mut alias)?;
        }

        let device = Self {
            socket: AsyncFd::new(control)?,
            name,
            index,
        };
        // The virtual subnets. The kernel may already have added the IPv6
        // prefix route for the address; that is not an error.
        let mut subnets = vec![(IpAddr::V4(address.0), address.1)];
        subnets.extend(address_v6.map(|(address, prefix)| (IpAddr::V6(address), prefix)));
        for (address, prefix) in subnets {
            let full = if address.is_ipv4() { 32 } else { 128 };
            if prefix >= full {
                continue;
            }
            let added = device.add_route(network_of(address, prefix), prefix);
            if added
                .as_ref()
                .is_err_and(|error| error.raw_os_error() != Some(libc::EEXIST))
            {
                return added.map(|()| device);
            }
        }
        Ok(device)
    }

    /// The name the kernel gave the interface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Routes `network`/`prefix` into this interface. The kernel removes
    /// the route with the interface.
    pub fn add_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        write_route(&route_message(libc::RTM_ADD, self.index, network, prefix))
    }

    /// Removes a route [`add_route`](Self::add_route) added.
    pub fn remove_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        write_route(&route_message(
            libc::RTM_DELETE,
            self.index,
            network,
            prefix,
        ))
    }

    /// Reads one IP packet.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut frame = vec![0u8; buffer.len() + FAMILY_V4.len()];
        loop {
            let mut guard = self.socket.readable().await?;
            match guard.try_io(|socket| {
                // SAFETY: the frame buffer is valid for its length.
                let read = unsafe {
                    libc::read(
                        socket.get_ref().as_raw_fd(),
                        frame.as_mut_ptr().cast(),
                        frame.len(),
                    )
                };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            }) {
                Ok(Ok(read)) if read <= FAMILY_V4.len() => continue,
                Ok(Ok(read)) => {
                    let packet = &frame[FAMILY_V4.len()..read];
                    buffer[..packet.len()].copy_from_slice(packet);
                    return Ok(packet.len());
                }
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one IP packet.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        let family = match packet.first().map(|byte| byte >> 4) {
            Some(4) => FAMILY_V4,
            Some(6) => FAMILY_V6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not an IP packet",
                ))
            }
        };
        let mut frame = Vec::with_capacity(packet.len() + family.len());
        frame.extend_from_slice(&family);
        frame.extend_from_slice(packet);
        loop {
            let mut guard = self.socket.writable().await?;
            match guard.try_io(|socket| {
                // SAFETY: the frame is valid for its length.
                let written = unsafe {
                    libc::write(
                        socket.get_ref().as_raw_fd(),
                        frame.as_ptr().cast(),
                        frame.len(),
                    )
                };
                if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(written as usize)
                }
            }) {
                Ok(result) => return result.map(|written| written.saturating_sub(family.len())),
                Err(_would_block) => continue,
            }
        }
    }
}

/// The address bytes of a socket address, as many as its length covers
/// (masks from `getifaddrs` may be cut short), padded with zeros.
fn sockaddr_bytes<const N: usize>(sockaddr: *const libc::sockaddr, offset: usize) -> [u8; N] {
    let mut bytes = [0u8; N];
    // SAFETY: a socket address from `getifaddrs` is valid for its length.
    unsafe {
        let length = usize::from((*sockaddr).sa_len);
        if length > offset {
            let available = (length - offset).min(N);
            std::ptr::copy_nonoverlapping(
                sockaddr.cast::<u8>().add(offset),
                bytes.as_mut_ptr(),
                available,
            );
        }
    }
    bytes
}

fn prefix_of(mask: &[u8]) -> u8 {
    let ones: u32 = mask.iter().map(|byte| byte.count_ones()).sum();
    u8::try_from(ones).unwrap_or(u8::MAX)
}

/// The address networks of every interface but loopback and those `skip`
/// names.
pub fn local_networks(skip: impl Fn(&str) -> bool) -> io::Result<Vec<(IpAddr, u8)>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `head` with a list freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut networks = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` points into the list `getifaddrs` returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if entry.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0 {
            continue;
        }
        // SAFETY: a non-null name is a C string.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if skip(&name.to_string_lossy()) {
            continue;
        }
        // SAFETY: a non-null address from `getifaddrs`.
        let family = libc::c_int::from(unsafe { (*entry.ifa_addr).sa_family });
        let network = match family {
            libc::AF_INET => Some((
                IpAddr::V4(Ipv4Addr::from(sockaddr_bytes::<4>(entry.ifa_addr, 4))),
                prefix_of(&sockaddr_bytes::<4>(entry.ifa_netmask, 4)),
            )),
            libc::AF_INET6 => {
                let mut bytes = sockaddr_bytes::<16>(entry.ifa_addr, 8);
                // The kernel keeps the scope of link-local addresses in
                // bytes 2 and 3.
                if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
                    bytes[2] = 0;
                    bytes[3] = 0;
                }
                Some((
                    IpAddr::V6(Ipv6Addr::from(bytes)),
                    prefix_of(&sockaddr_bytes::<16>(entry.ifa_netmask, 8)),
                ))
            }
            _ => None,
        };
        networks.extend(network);
    }
    // SAFETY: `head` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(networks)
}

/// The interface's IPv4 address and prefix, and its IPv6 one if any.
pub type InterfaceAddresses = ((Ipv4Addr, u8), Option<(Ipv6Addr, u8)>);

/// Splits the settings' addresses into the shapes [`Tun::create`] takes.
pub fn addresses(
    address: IpAddr,
    prefix: u8,
    address_v6: Option<(IpAddr, u8)>,
) -> Option<InterfaceAddresses> {
    let IpAddr::V4(v4) = address else {
        return None;
    };
    let v6 = match address_v6 {
        None => None,
        Some((IpAddr::V6(v6), prefix)) => Some((v6, prefix)),
        Some((IpAddr::V4(_), _)) => return None,
    };
    Some(((v4, prefix), v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_have_the_kernel_sizes() {
        assert_eq!(std::mem::size_of::<IfReq>(), 32);
        assert_eq!(std::mem::size_of::<IfAliasReq>(), 64);
        assert_eq!(std::mem::size_of::<In6AliasReq>(), 128);
        assert_eq!(std::mem::size_of::<libc::sockaddr_dl>(), 20);
        // The ioctl numbers encode those sizes.
        assert_eq!((SIOCAIFADDR >> 16) & 0x1fff, 64);
        assert_eq!((SIOCAIFADDR_IN6 >> 16) & 0x1fff, 128);
        assert_eq!((SIOCSIFMTU >> 16) & 0x1fff, 32);
    }

    #[test]
    fn utun_names_pick_the_unit() {
        assert_eq!(unit_for("utun0"), 1);
        assert_eq!(unit_for("utun12"), 13);
        assert_eq!(unit_for("anixmesh0"), 0);
        assert_eq!(unit_for("utun"), 0);
        assert_eq!(unit_for("utunx"), 0);
    }

    #[test]
    fn masks_and_networks_follow_the_prefix() {
        assert_eq!(ipv4_mask(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(32), Ipv4Addr::BROADCAST);
        assert_eq!(
            ipv6_mask(64),
            "ffff:ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            network_of(IpAddr::V4(Ipv4Addr::new(10, 144, 0, 5)), 24),
            IpAddr::V4(Ipv4Addr::new(10, 144, 0, 0))
        );
        assert_eq!(
            network_of("fd00::5".parse().unwrap(), 64),
            "fd00::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn route_messages_name_the_interface_and_mask() {
        let header = std::mem::size_of::<libc::rt_msghdr>();
        let message = route_message(
            libc::RTM_ADD,
            9,
            IpAddr::V4(Ipv4Addr::new(192, 168, 10, 0)),
            24,
        );
        // Header, destination (16), link (20), mask (16).
        assert_eq!(message.len(), header + 16 + 20 + 16);
        assert_eq!(
            usize::from(u16::from_ne_bytes([message[0], message[1]])),
            message.len()
        );
        assert_eq!(message[2], libc::RTM_VERSION as u8);
        assert_eq!(message[3], libc::RTM_ADD as u8);
        assert_eq!(&message[header + 4..header + 8], &[192, 168, 10, 0]);
        assert_eq!(message[header + 16 + 1], libc::AF_LINK as u8);
        assert_eq!(
            u16::from_ne_bytes([message[header + 18], message[header + 19]]),
            9
        );
        assert_eq!(
            &message[header + 36 + 4..header + 36 + 8],
            &[255, 255, 255, 0]
        );

        // A host route has no mask.
        let host = route_message(
            libc::RTM_DELETE,
            9,
            IpAddr::V6("fd00::1".parse().unwrap()),
            128,
        );
        assert_eq!(host.len(), header + 28 + 20);
    }

    #[test]
    fn the_machine_has_some_networks_and_never_loopback() {
        let networks = local_networks(|_| false).expect("getifaddrs");
        assert!(networks.iter().all(|(address, _)| !address.is_loopback()));
    }
}
