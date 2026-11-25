//! Windows side of [`super`]: routes from `GetIpForwardTable2`, interfaces
//! from `GetIfTable2`, addresses from `GetUnicastIpAddressTable`.
//!
//! Windows keeps one routing table per address family, so the dump sees
//! every route another program adds. An interface is virtual when its type
//! is a tunnel, PPP or a software adapter (`IF_TYPE_PROP_VIRTUAL`, which is
//! what Wintun and TAP adapters report), or it carries a tunnel type.
//! Hyper-V and WSL switches report Ethernet and count as physical, so their
//! networks are local, as they are on the machine.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use outbound_mesh::IpNet;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetIpForwardTable2, GetUnicastIpAddressTable, IF_TYPE_PPP,
    IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, MIB_IF_TABLE2,
    MIB_IPFORWARD_TABLE2, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

use super::{HostLink, HostRoute};

/// One interface row, reduced to what the overlap rule needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Interface {
    alias: String,
    kind: u32,
    tunnel_type: i32,
}

/// Whether an interface of this type is another program's virtual
/// interface.
fn is_virtual(kind: u32, tunnel_type: i32) -> bool {
    matches!(kind, IF_TYPE_PPP | IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL) || tunnel_type != 0
}

/// The address in a `SOCKADDR_INET`, `None` for other families.
fn address_of(sockaddr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family tells which member of the union is valid.
    unsafe {
        match sockaddr.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sockaddr.Ipv4.sin_addr.S_un.S_addr,
            )))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sockaddr.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn win32(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// Rows of a MIB table, copied out before the table is freed.
///
/// # Safety
///
/// `table` must point to a MIB table whose `NumEntries` rows of `Row` follow
/// the count, as the IP Helper functions return them.
unsafe fn rows<Table, Row: Copy>(
    table: *const Table,
    count: impl Fn(&Table) -> u32,
    first: impl Fn(&Table) -> *const Row,
) -> Vec<Row> {
    // SAFETY: the caller guarantees the layout.
    unsafe {
        let table = &*table;
        let count = count(table) as usize;
        std::slice::from_raw_parts(first(table), count).to_vec()
    }
}

fn interfaces() -> io::Result<HashMap<u32, Interface>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: the function fills `table`, freed below.
    win32(unsafe { GetIfTable2(&mut table) })?;
    // SAFETY: `GetIfTable2` returned a valid table.
    let rows = unsafe {
        rows(
            table,
            |table| table.NumEntries,
            |table| table.Table.as_ptr(),
        )
    };
    // SAFETY: freed once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(rows
        .iter()
        .map(|row| {
            let end = row
                .Alias
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(row.Alias.len());
            (
                row.InterfaceIndex,
                Interface {
                    alias: String::from_utf16_lossy(&row.Alias[..end]),
                    kind: row.Type,
                    tunnel_type: row.TunnelType,
                },
            )
        })
        .collect())
}

/// Every route of both families, with the interface it leaves through.
pub fn host_routes() -> io::Result<Vec<HostRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the function fills `table`, freed below.
    let code = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if code == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    win32(code)?;
    // SAFETY: `GetIpForwardTable2` returned a valid table.
    let rows = unsafe {
        rows(
            table,
            |table| table.NumEntries,
            |table| table.Table.as_ptr(),
        )
    };
    // SAFETY: freed once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(rows
        .iter()
        .filter(|row| !row.Loopback)
        .filter_map(|row| {
            let address = address_of(&row.DestinationPrefix.Prefix)?;
            let destination = IpNet::new(address, row.DestinationPrefix.PrefixLength)?.trunc();
            Some(HostRoute {
                destination,
                interfaces: vec![row.InterfaceIndex],
            })
        })
        .collect())
}

/// Every interface by index, named by its alias (the name Windows network
/// settings show).
pub fn host_links() -> io::Result<HashMap<u32, HostLink>> {
    Ok(interfaces()?
        .into_iter()
        .map(|(index, interface)| {
            (
                index,
                HostLink {
                    is_virtual: is_virtual(interface.kind, interface.tunnel_type),
                    name: interface.alias,
                },
            )
        })
        .collect())
}

/// The address networks of every interface but loopback and those `skip`
/// names (by alias).
pub fn local_networks(skip: impl Fn(&str) -> bool) -> io::Result<Vec<(IpAddr, u8)>> {
    let interfaces = interfaces()?;
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the function fills `table`, freed below.
    let code = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    if code == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    win32(code)?;
    // SAFETY: `GetUnicastIpAddressTable` returned a valid table.
    let rows = unsafe {
        rows(
            table,
            |table| table.NumEntries,
            |table| table.Table.as_ptr(),
        )
    };
    // SAFETY: freed once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(rows
        .iter()
        .filter(|row| {
            interfaces.get(&row.InterfaceIndex).is_none_or(|interface| {
                interface.kind != IF_TYPE_SOFTWARE_LOOPBACK && !skip(&interface.alias)
            })
        })
        .filter_map(|row| {
            let address = address_of(&row.Address)?;
            (!address.is_loopback()).then_some((address, row.OnLinkPrefixLength))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_interfaces_are_tunnels_and_software_adapters() {
        assert!(is_virtual(IF_TYPE_PROP_VIRTUAL, 0));
        assert!(is_virtual(IF_TYPE_TUNNEL, 0));
        assert!(is_virtual(IF_TYPE_PPP, 0));
        // Ethernet (6) and Wi-Fi (71) are physical unless they tunnel.
        assert!(!is_virtual(6, 0));
        assert!(!is_virtual(71, 0));
        assert!(is_virtual(6, 14));
    }

    #[test]
    fn socket_addresses_give_their_address() {
        // SAFETY: an all-zero union is valid.
        let mut v4: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        v4.si_family = AF_INET;
        v4.Ipv4.sin_addr.S_un.S_addr = u32::from(Ipv4Addr::new(100, 64, 1, 2)).to_be();
        assert_eq!(
            address_of(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2)))
        );
        // SAFETY: as above.
        let mut v6: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        v6.si_family = AF_INET6;
        let address: Ipv6Addr = "fd7a:115c:a1e0::1".parse().unwrap();
        v6.Ipv6.sin6_addr.u.Byte = address.octets();
        assert_eq!(address_of(&v6), Some(IpAddr::V6(address)));
        // SAFETY: as above.
        let other: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        assert_eq!(address_of(&other), None);
    }

    #[test]
    fn the_host_tables_can_be_read() {
        let links = host_links().expect("interfaces");
        assert!(!links.is_empty());
        let routes = host_routes().expect("routes");
        assert!(routes
            .iter()
            .all(|route| route.destination == route.destination.trunc()));
        let networks = local_networks(|_| false).expect("addresses");
        assert!(networks.iter().all(|(address, _)| !address.is_loopback()));
    }
}
