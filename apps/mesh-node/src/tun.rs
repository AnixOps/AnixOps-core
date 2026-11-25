//! The Linux virtual interface of `run`: a TUN device without packet
//! information, its addresses, MTU and link state set with the classic
//! interface ioctls so that no `ip` program is needed (OpenWrt images often
//! have none).

// ioctl request numbers are `c_ulong` with glibc and `c_int` with musl
// (OpenWrt); the casts below are only no-ops on one of them.
#![allow(clippy::unnecessary_cast)]

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use tokio::io::unix::AsyncFd;

/// Longest interface name, without the terminating zero.
pub const MAX_NAME_LEN: usize = libc::IFNAMSIZ - 1;

/// `struct ifreq`: the name and a union of at most 24 bytes. A larger
/// buffer than the kernel's own is harmless; a smaller one is not.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must be 1 to 15 bytes without NUL",
            ));
        }
        let mut request = Self {
            name: [0; libc::IFNAMSIZ],
            data: [0; 24],
        };
        request.name[..bytes.len()].copy_from_slice(bytes);
        Ok(request)
    }

    fn name(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    fn set_short(&mut self, value: libc::c_short) {
        self.data[..2].copy_from_slice(&value.to_ne_bytes());
    }

    fn short(&self) -> libc::c_short {
        libc::c_short::from_ne_bytes([self.data[0], self.data[1]])
    }

    fn set_int(&mut self, value: libc::c_int) {
        self.data[..4].copy_from_slice(&value.to_ne_bytes());
    }

    fn int(&self) -> libc::c_int {
        libc::c_int::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    /// A `sockaddr_in` with port 0.
    fn set_ipv4(&mut self, address: Ipv4Addr) {
        self.data = [0; 24];
        let family = libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(2);
        self.data[..2].copy_from_slice(&family.to_ne_bytes());
        self.data[4..8].copy_from_slice(&address.octets());
    }
}

/// `struct in6_ifreq`.
#[repr(C)]
struct In6IfReq {
    address: [u8; 16],
    prefix: u32,
    index: libc::c_int,
}

fn ioctl<T>(fd: &OwnedFd, request: libc::c_ulong, argument: &mut T) -> io::Result<()> {
    // SAFETY: every request used here reads or writes one `T` that is
    // laid out as the kernel expects (`IfReq` is at least as large as
    // `struct ifreq`), and the pointer lives for the call.
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            request as _,
            std::ptr::from_mut(argument).cast::<libc::c_void>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socket(family: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain socket creation; the descriptor is owned below.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ipv4_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(bits)
}

/// An open TUN device. Closing it removes the interface.
pub struct Tun {
    file: AsyncFd<File>,
    name: String,
    index: libc::c_int,
}

impl Tun {
    /// Creates the interface, gives it `address`/`prefix` (and the IPv6
    /// address if any), sets the MTU and brings it up. The kernel adds the
    /// routes of the virtual subnets from the prefixes.
    pub fn create(
        name: &str,
        address: (Ipv4Addr, u8),
        address_v6: Option<(Ipv6Addr, u8)>,
        mtu: u16,
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")?;
        let device = OwnedFd::from(file);
        let mut request = IfReq::new(name)?;
        let flags = libc::IFF_TUN | libc::IFF_NO_PI;
        request.set_short(libc::c_short::try_from(flags).unwrap_or(0));
        ioctl(&device, libc::TUNSETIFF as libc::c_ulong, &mut request)?;
        let name = request.name();

        let control = socket(libc::AF_INET)?;
        let mut request = IfReq::new(&name)?;
        request.set_ipv4(address.0);
        ioctl(&control, libc::SIOCSIFADDR as libc::c_ulong, &mut request)?;
        let mut request = IfReq::new(&name)?;
        request.set_ipv4(ipv4_mask(address.1));
        ioctl(
            &control,
            libc::SIOCSIFNETMASK as libc::c_ulong,
            &mut request,
        )?;
        let mut request = IfReq::new(&name)?;
        request.set_int(libc::c_int::from(mtu));
        ioctl(&control, libc::SIOCSIFMTU as libc::c_ulong, &mut request)?;
        let mut request = IfReq::new(&name)?;
        ioctl(&control, libc::SIOCGIFFLAGS as libc::c_ulong, &mut request)?;
        let up = libc::c_short::try_from(libc::IFF_UP | libc::IFF_RUNNING).unwrap_or(0);
        let flags = request.short() | up;
        request.set_short(flags);
        ioctl(&control, libc::SIOCSIFFLAGS as libc::c_ulong, &mut request)?;

        let mut request = IfReq::new(&name)?;
        ioctl(&control, libc::SIOCGIFINDEX as libc::c_ulong, &mut request)?;
        let index = request.int();
        if let Some((address, prefix)) = address_v6 {
            let control = socket(libc::AF_INET6)?;
            let mut v6 = In6IfReq {
                address: address.octets(),
                prefix: u32::from(prefix),
                index,
            };
            ioctl(&control, libc::SIOCSIFADDR as libc::c_ulong, &mut v6)?;
        }

        Ok(Self {
            file: AsyncFd::new(File::from(device))?,
            name,
            index,
        })
    }

    /// The name the kernel gave the interface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Routes `network`/`prefix` into this interface. The kernel removes
    /// the route with the interface.
    pub fn add_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        self.route(libc::SIOCADDRT as libc::c_ulong, network, prefix)
    }

    /// Removes a route [`add_route`](Self::add_route) added.
    pub fn remove_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        self.route(libc::SIOCDELRT as libc::c_ulong, network, prefix)
    }

    fn route(&self, request: libc::c_ulong, network: IpAddr, prefix: u8) -> io::Result<()> {
        match network {
            IpAddr::V4(network) => {
                let device = CString::new(self.name.as_str())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                // SAFETY: an all-zero `rtentry` is valid (null pointers,
                // zero numbers).
                let mut entry: libc::rtentry = unsafe { std::mem::zeroed() };
                write_sockaddr_in(&mut entry.rt_dst, network);
                write_sockaddr_in(&mut entry.rt_genmask, ipv4_mask(prefix));
                entry.rt_flags = libc::RTF_UP as libc::c_ushort;
                entry.rt_metric = 1;
                // The kernel only reads the name.
                entry.rt_dev = device.as_ptr().cast_mut();
                ioctl(&socket(libc::AF_INET)?, request, &mut entry)
            }
            IpAddr::V6(network) => {
                // SAFETY: an all-zero `in6_rtmsg` is valid.
                let mut message: libc::in6_rtmsg = unsafe { std::mem::zeroed() };
                message.rtmsg_dst.s6_addr = network.octets();
                message.rtmsg_dst_len = u16::from(prefix);
                message.rtmsg_metric = 1;
                message.rtmsg_flags = libc::RTF_UP as u32;
                message.rtmsg_ifindex = self.index;
                ioctl(&socket(libc::AF_INET6)?, request, &mut message)
            }
        }
    }

    /// Reads one IP packet.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.file.readable().await?;
            match guard.try_io(|file| {
                let mut reader = file.get_ref();
                reader.read(buffer)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one IP packet.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.file.writable().await?;
            match guard.try_io(|file| {
                let mut writer = file.get_ref();
                writer.write(packet)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn write_sockaddr_in(target: &mut libc::sockaddr, address: Ipv4Addr) {
    let mut bytes = [0u8; 16];
    let family = libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(2);
    bytes[..2].copy_from_slice(&family.to_ne_bytes());
    bytes[4..8].copy_from_slice(&address.octets());
    // SAFETY: `sockaddr` is 16 plain bytes; the bytes are a `sockaddr_in`.
    *target = unsafe { std::mem::transmute::<[u8; 16], libc::sockaddr>(bytes) };
}

fn prefix_of(mask: &[u8]) -> u8 {
    let ones: u32 = mask.iter().map(|byte| byte.count_ones()).sum();
    u8::try_from(ones).unwrap_or(u8::MAX)
}

/// The networks of every interface but loopback and `skip` (the mesh's own
/// interface), for the overlap rule of spec §15.4.
pub fn local_networks(skip: &str) -> io::Result<Vec<(IpAddr, u8)>> {
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
        if name.to_bytes() == skip.as_bytes() {
            continue;
        }
        // SAFETY: the address and mask point to socket addresses of the
        // family the address names.
        let network = unsafe {
            match libc::c_int::from((*entry.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let address = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                    let mask = &*entry.ifa_netmask.cast::<libc::sockaddr_in>();
                    Some((
                        IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))),
                        prefix_of(&mask.sin_addr.s_addr.to_ne_bytes()),
                    ))
                }
                libc::AF_INET6 => {
                    let address = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                    let mask = &*entry.ifa_netmask.cast::<libc::sockaddr_in6>();
                    Some((
                        IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                        prefix_of(&mask.sin6_addr.s6_addr),
                    ))
                }
                _ => None,
            }
        };
        networks.extend(network);
    }
    // SAFETY: `head` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(networks)
}

/// Splits the settings' addresses into the shapes [`Tun::create`] takes.
pub fn addresses(
    address: IpAddr,
    prefix: u8,
    address_v6: Option<(IpAddr, u8)>,
) -> Option<((Ipv4Addr, u8), Option<(Ipv6Addr, u8)>)> {
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
    fn masks_follow_the_prefix() {
        assert_eq!(ipv4_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(ipv4_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(31), Ipv4Addr::new(255, 255, 255, 254));
        assert_eq!(ipv4_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn interface_names_are_checked() {
        assert!(IfReq::new("").is_err());
        assert!(IfReq::new("a\0b").is_err());
        assert!(IfReq::new("sixteen-letters!").is_err());
        let request = IfReq::new("mesh0").expect("short name");
        assert_eq!(request.name(), "mesh0");
    }

    #[test]
    fn the_request_holds_a_whole_kernel_request() {
        assert!(std::mem::size_of::<IfReq>() >= std::mem::size_of::<libc::ifreq>());
    }

    #[test]
    fn an_ipv4_address_is_a_socket_address() {
        let mut request = IfReq::new("mesh0").expect("name");
        request.set_ipv4(Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(&request.data[4..8], &[10, 1, 2, 3]);
        let family = libc::sa_family_t::from_ne_bytes([request.data[0], request.data[1]]);
        assert_eq!(libc::c_int::from(family), libc::AF_INET);
    }

    #[test]
    fn prefixes_count_mask_bits() {
        assert_eq!(prefix_of(&[255, 255, 255, 0]), 24);
        assert_eq!(prefix_of(&[0; 16]), 0);
        assert_eq!(prefix_of(&[255; 16]), 128);
    }

    #[test]
    fn a_route_destination_is_a_socket_address() {
        // SAFETY: test-only zeroed plain struct.
        let mut target: libc::sockaddr = unsafe { std::mem::zeroed() };
        write_sockaddr_in(&mut target, Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(libc::c_int::from(target.sa_family), libc::AF_INET);
        let data: Vec<u8> = target.sa_data.iter().map(|byte| *byte as u8).collect();
        assert_eq!(&data[2..6], &[192, 168, 10, 0]);
    }

    #[test]
    fn the_machine_has_some_networks_and_never_loopback() {
        let networks = local_networks("none-such").expect("getifaddrs");
        assert!(networks.iter().all(|(address, _)| !address.is_loopback()));
    }

    #[test]
    fn address_families_must_match() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(addresses(v6, 64, None).is_none());
        assert!(addresses(v4, 24, Some((v4, 24))).is_none());
        let (ipv4, ipv6) = addresses(v4, 24, Some((v6, 64))).expect("matching families");
        assert_eq!(ipv4, (Ipv4Addr::new(10, 0, 0, 1), 24));
        assert_eq!(ipv6, Some((Ipv6Addr::LOCALHOST, 64)));
    }
}
