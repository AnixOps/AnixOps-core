//! Sockets pinned to a named network interface, for a DIRECT outbound bound
//! to one (Surge `direct, interface=...`): traffic that must leave through a
//! company VPN's interface, or through Wi-Fi while another interface holds
//! the default route.
//!
//! - Linux and Android: `SO_BINDTODEVICE` with the interface name (Linux 5.7
//!   and later allow it without `CAP_NET_RAW`).
//! - macOS and iOS: `IP_BOUND_IF` / `IPV6_BOUND_IF` with the index of the
//!   interface (`if_nametoindex`, such as `en0` or `utun4`).
//! - Windows: `IP_UNICAST_IF` / `IPV6_UNICAST_IF` with the index of the
//!   adapter whose alias (the name in Network Connections, such as
//!   `Ethernet` or the VPN's name) is given.
//!
//! The interface is looked up for every socket, so a VPN that comes up
//! later is used as soon as it exists. While it does not exist the socket
//! fails with [`io::ErrorKind::NotFound`]: a flow meant for the VPN never
//! leaves through another interface. The process-wide socket protector
//! ([`engine_outbound::protect`]) is not applied to these sockets; the
//! interface given here replaces its pin.

use std::io;
use std::net::SocketAddr;

use engine_outbound::protect::RawSocketHandle;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Longest interface name accepted (Windows aliases can be long; Linux
/// names stop at 15 bytes and are checked when a socket is bound).
pub const MAX_INTERFACE_NAME_LEN: usize = 256;

/// Whether `name` can name an interface: not empty, not too long, no
/// control characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_INTERFACE_NAME_LEN && !name.chars().any(char::is_control)
}

/// A TCP connection to `target` that leaves through interface `name`.
pub async fn connect_tcp(name: &str, target: SocketAddr) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    bind(raw(&socket), name, target.is_ipv6())?;
    socket.connect(target).await
}

/// A UDP socket connected to `target` that leaves through interface `name`.
pub async fn connect_udp(name: &str, target: SocketAddr) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(engine_outbound::protect::unspecified_for(target))?;
    bind(raw(&socket), name, target.is_ipv6())?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    socket.connect(target).await?;
    Ok(socket)
}

#[cfg(unix)]
fn raw<S: std::os::fd::AsRawFd>(socket: &S) -> RawSocketHandle {
    socket.as_raw_fd()
}

#[cfg(windows)]
fn raw<S: std::os::windows::io::AsRawSocket>(socket: &S) -> RawSocketHandle {
    socket.as_raw_socket()
}

fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "bound interface does not exist")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind(socket: RawSocketHandle, name: &str, _ipv6: bool) -> io::Result<()> {
    // IFNAMSIZ is 16 with the terminating NUL.
    if name.len() >= 16 || name.contains('\0') {
        return Err(not_found());
    }
    // SAFETY: `socket` is an open socket owned by the caller; the name
    // bytes live for the call with the length passed.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODEV) {
            Err(not_found())
        } else {
            Err(error)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind(socket: RawSocketHandle, name: &str, ipv6: bool) -> io::Result<()> {
    /// `IP_BOUND_IF` / `IPV6_BOUND_IF` from `<netinet/in.h>` / `<netinet6/in6.h>`.
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;

    let name = std::ffi::CString::new(name).map_err(|_| not_found())?;
    // SAFETY: `name` is a NUL-terminated string that lives for the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(not_found());
    }
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    };
    let value: libc::c_uint = index;
    // SAFETY: `socket` is an open socket owned by the caller, and `value`
    // lives for the call with the length passed.
    let result = unsafe {
        libc::setsockopt(
            socket,
            level,
            option,
            (&value as *const libc::c_uint).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn bind(socket: RawSocketHandle, name: &str, ipv6: bool) -> io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET};

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;

    if name.contains('\0') {
        return Err(not_found());
    }
    let alias: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `alias` is NUL-terminated UTF-16 and `luid` is a valid out
    // parameter, both living for the call.
    if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } != 0 {
        return Err(not_found());
    }
    let mut index = 0u32;
    // SAFETY: `luid` was filled above; `index` is a valid out parameter.
    if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != 0 || index == 0 {
        return Err(not_found());
    }
    let set = |level: i32, option: i32, value: u32| {
        // SAFETY: `socket` is an open socket owned by the caller, and
        // `value` lives for the call with the length passed.
        let result = unsafe {
            setsockopt(
                socket as SOCKET,
                level,
                option,
                (&value as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    // IP_UNICAST_IF takes the IPv4 index in network byte order,
    // IPV6_UNICAST_IF in host order.
    if ipv6 {
        set(IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        set(IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
fn bind(_socket: RawSocketHandle, _name: &str, _ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "binding to an interface is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked() {
        assert!(valid_name("utun4"));
        assert!(valid_name("Corp VPN"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad\nname"));
        assert!(!valid_name(&"x".repeat(MAX_INTERFACE_NAME_LEN + 1)));
    }

    #[tokio::test]
    async fn a_missing_interface_fails_without_leaving_elsewhere() {
        let target: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let error = connect_udp("anixops-none0", target).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        let error = connect_tcp("anixops-none0", target).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    }

    /// The loopback interface exists everywhere tests run; a socket bound
    /// to it reaches a loopback listener.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_bound_socket_connects_through_its_interface() {
        let name = if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        connect_tcp(name, address).await.unwrap();
        accept.await.unwrap().unwrap();
    }
}
