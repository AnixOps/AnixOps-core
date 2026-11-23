//! Keeps other devices that use the LAN share (`crate::lan_share`) from
//! reaching this computer itself through DIRECT.
//!
//! A phone that sets this computer as its Wi-Fi proxy asks for any
//! destination it likes. A flow that a rule (or the direct mode) sends DIRECT
//! is dialed from this computer, so without a check `CONNECT 127.0.0.1:6379`
//! from any device on the same network would reach services that listen on
//! loopback only (databases, the Docker API, development servers, the
//! client's own control and metrics ports), and the addresses of other
//! interfaces (Docker bridges, VPN and mesh tunnels) would be one hop away.
//!
//! The [`crate::connections::Dispatcher`] checks every DIRECT flow that
//! carries a [`LanPeer`] after routing and name resolution, and dials the
//! checked address itself, so a name that resolves to loopback (DNS
//! rebinding) is refused as well. Refused, whatever the rules say:
//!
//! - loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`),
//!   link-local (`169.254.0.0/16`, `fe80::/10`), multicast and broadcast
//!   addresses, IPv4-mapped IPv6 forms included;
//! - the names `localhost` and `*.localhost` (RFC 6761), before any lookup;
//! - the addresses of this computer's interfaces, the one the device reached
//!   the share on included: a service bound to all interfaces that the host
//!   firewall keeps from the network (file sharing, remote management, a
//!   development server allowed on private networks only) would otherwise be
//!   one proxy hop away, since the proxy dials it from this computer and the
//!   firewall never sees the device. The one exception is the share's own
//!   port on that address ([`LanPeer::share_port`]), which the device
//!   already reaches directly: a phone that opens the setup page
//!   `http://<computer>:<port>/` while it uses the proxy is answered by the
//!   share itself;
//! - with [`LanPeer::block_private_networks`] (off by default), every private
//!   destination as well (RFC 1918, `100.64.0.0/10`, IPv6 ULA `fc00::/7`), so
//!   the device cannot reach other machines of the networks this computer
//!   is on (a company VPN, a lab).
//!
//! Flows from loopback clients (this computer's own programs using the
//! share's port) carry no [`LanPeer`] and are not checked; flows through a
//! proxy node are resolved on the far side and are not checked either. A
//! `redirects` line that names a new host is the user's own choice and is
//! not checked: it is how a user lets phones reach a development server on
//! this computer.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A flow opened by another device on the local network through the LAN
/// share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanPeer {
    /// This computer's address the device reached the share on. Refused
    /// like every other interface address of this computer, except on
    /// [`Self::share_port`].
    pub via: IpAddr,
    /// The share's own listener port: the only port of [`Self::via`] the
    /// device may reach through DIRECT, since it reaches it directly anyway
    /// (the setup page).
    pub share_port: u16,
    /// Also refuse private destinations; see the module documentation.
    pub block_private_networks: bool,
}

/// The error a refused flow shows in the connection list.
pub const REFUSED: &str = "lan_share_local_target";

/// The error a refused flow fails with. `PermissionDenied`, so a policy
/// group does not take it for a dead node.
pub fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "lan share: devices on the local network may not reach this computer's \
         loopback, link-local or interface addresses through DIRECT",
    )
}

/// Whether `name` is `localhost` or a name under it (RFC 6761), which every
/// resolver answers with loopback.
pub fn is_local_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost")
}

/// Whether `peer` may not reach `target` through DIRECT. `own` tells this
/// computer's interface addresses; see [`is_own_address`].
pub fn refuses(peer: LanPeer, target: SocketAddr, own: impl Fn(IpAddr) -> bool) -> bool {
    let address = target.ip().to_canonical();
    if always_refused(address) {
        return true;
    }
    // The share itself, on the address the device reached it on: nothing
    // the device cannot open without the proxy.
    if address == peer.via.to_canonical() && target.port() == peer.share_port {
        return false;
    }
    if peer.block_private_networks && is_private(address) {
        return true;
    }
    own(address)
}

/// Loopback, unspecified, link-local, multicast and broadcast addresses.
fn always_refused(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                // 0.0.0.0/8: "this network"; connecting to 0.0.0.0 reaches
                // this computer on Linux and macOS.
                || address.octets()[0] == 0
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || is_link_local_v6(address)
                || address.is_multicast()
        }
    }
}

/// `fe80::/10`.
fn is_link_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

/// RFC 1918, RFC 6598 shared (`100.64.0.0/10`) and IPv6 unique local
/// (`fc00::/7`) addresses.
fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || is_shared_v4(address),
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

/// `100.64.0.0/10` (carrier-grade NAT, mesh VPNs).
fn is_shared_v4(address: Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    a == 100 && (64..128).contains(&b)
}

/// Whether `address` belongs to one of this computer's interfaces that are
/// up. Looked up for every check, so an interface that came up after the
/// share started (a VPN) counts at once.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn is_own_address(address: IpAddr) -> bool {
    interface_addresses().contains(&address.to_canonical())
}

/// Whether `address` belongs to this computer: binding a socket to it works
/// only then.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn is_own_address(address: IpAddr) -> bool {
    std::net::UdpSocket::bind(std::net::SocketAddr::new(address.to_canonical(), 0)).is_ok()
}

/// IPv4 and IPv6 addresses of the interfaces that are up, loopback included.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn interface_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that stays valid until
    // freeifaddrs, which is called once below; entries are only read, and
    // each address is read as the socket address type its family names.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            let flags: u32 = entry.ifa_flags;
            let up = flags & (libc::IFF_UP as u32) != 0;
            if up && !entry.ifa_addr.is_null() {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let address = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        addresses.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            address.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let address = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        addresses.push(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> LanPeer {
        LanPeer {
            via: "192.168.1.5".parse().unwrap(),
            share_port: 8899,
            block_private_networks: false,
        }
    }

    fn nothing_own(_: IpAddr) -> bool {
        false
    }

    /// `address` (an IP address) on port 443.
    fn at(address: &str) -> SocketAddr {
        SocketAddr::new(address.parse().unwrap(), 443)
    }

    fn is_refused(address: &str) -> bool {
        refuses(peer(), at(address), nothing_own)
    }

    #[test]
    fn loopback_and_other_local_addresses_are_refused() {
        for address in [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "0.1.2.3",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.1.1",
            "fe80::1",
            "febf::1",
            "ff02::1",
        ] {
            assert!(is_refused(address), "{address}");
        }
    }

    #[test]
    fn other_devices_and_the_internet_are_reachable() {
        for address in [
            "192.168.213.40",
            "10.0.0.8",
            "172.16.3.4",
            "100.64.1.1",
            "fd00::8",
            "8.8.8.8",
            "2001:db8::1",
            "::ffff:192.168.213.40",
            "fec0::1",
        ] {
            assert!(!is_refused(address), "{address}");
        }
    }

    #[test]
    fn private_networks_are_refused_on_request() {
        let strict = LanPeer {
            block_private_networks: true,
            ..peer()
        };
        for address in [
            "192.168.213.40",
            "10.0.0.8",
            "172.31.0.1",
            "100.127.0.1",
            "fd00::8",
            "::ffff:10.1.1.1",
        ] {
            assert!(refuses(strict, at(address), nothing_own), "{address}");
        }
        for address in ["8.8.8.8", "100.128.0.1", "2001:db8::1"] {
            assert!(!refuses(strict, at(address), nothing_own), "{address}");
        }
    }

    #[test]
    fn own_addresses_are_refused_the_share_address_included() {
        let own = |address: IpAddr| {
            ["192.168.1.5", "172.17.0.1", "100.100.1.2", "fd7a::5"]
                .iter()
                .any(|own| own.parse::<IpAddr>().unwrap() == address)
        };
        let refused = |target: &str| refuses(peer(), target.parse().unwrap(), own);
        for target in [
            "172.17.0.1:80",
            "100.100.1.2:22",
            "[fd7a::5]:443",
            "[::ffff:172.17.0.1]:2375",
            // The address the phone reached: services the host firewall
            // keeps from the network (SMB, RPC, a development server).
            "192.168.1.5:445",
            "192.168.1.5:135",
            "192.168.1.5:3000",
            "[::ffff:192.168.1.5]:5985",
            // The share's port, but on another address of this computer.
            "172.17.0.1:8899",
        ] {
            assert!(refused(target), "{target}");
        }
        // Only the share itself, where the phone reached it.
        assert!(!refused("192.168.1.5:8899"));
        assert!(!refused("[::ffff:192.168.1.5]:8899"));
        assert!(!refused("192.168.213.40:3000"));
        // Loopback stays refused on the share's port too.
        assert!(refused("127.0.0.1:8899"));
        // With private networks refused, the share itself still answers.
        let strict = LanPeer {
            block_private_networks: true,
            ..peer()
        };
        assert!(!refuses(strict, "192.168.1.5:8899".parse().unwrap(), own));
        assert!(refuses(strict, "192.168.1.5:3000".parse().unwrap(), own));
    }

    #[test]
    fn localhost_names_are_local() {
        for name in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "app.localhost",
            "a.b.Localhost.",
        ] {
            assert!(is_local_name(name), "{name}");
        }
        for name in [
            "localhost.example.com",
            "mylocalhost",
            "example.com",
            "local",
        ] {
            assert!(!is_local_name(name), "{name}");
        }
    }

    #[test]
    fn this_computer_owns_its_loopback_address() {
        assert!(is_own_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_own_address("192.0.2.77".parse().unwrap()));
    }
}
