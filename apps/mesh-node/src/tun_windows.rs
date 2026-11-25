//! The Windows virtual interface of `run`: a Wintun adapter
//! (`platform_windows::tun`) that carries only the mesh's routes.
//!
//! The adapter is named like the Linux interface (`anixmesh0` unless
//! `--interface` says otherwise) and gets a GUID derived from that name, so
//! it never takes the client's adapter and a stale one left by a crash is
//! replaced at the next start. DNS stays the machine's own; nothing is
//! captured but the routes the node adds. `wintun.dll` is loaded from the
//! program's directory only.
//!
//! Wintun hands packets to a reader thread; they reach [`Tun::recv`]
//! through a bounded queue, and a full queue drops the packet as a full
//! interface would.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};

use platform_windows::tun::{
    default_wintun_dll_path, CaptureRoute, WindowsTun, WindowsTunSettings, WindowsTunWriter,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

pub use crate::host_routes::local_networks;

/// Packets queued between the reader thread and [`Tun::recv`].
const QUEUE: usize = 256;

/// Wintun ring size: 4 MiB, as the client uses.
const RING_CAPACITY: u32 = 0x0040_0000;

/// The adapter GUID for an adapter name: a name-based (version 5 layout)
/// UUID from a hash of the name, so each name keeps its GUID.
pub fn adapter_guid(name: &str) -> u128 {
    let digest = Sha256::digest(format!("anixops-mesh adapter {name}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    u128::from_be_bytes(bytes)
}

/// Another address in the adapter's IPv4 subnet. The adapter settings ask
/// for a DNS address even when none is announced; it is never used.
fn unused_dns(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let network = u32::from(address) & mask;
    let host = u32::from(address) & !mask;
    // The last host of the subnet, or the one before when that is us.
    let last = !mask - 1;
    let pick = if host == last { last - 1 } else { last };
    Ipv4Addr::from(network | pick)
}

/// The adapter settings for the mesh: only the given routes, no DNS, no
/// capture, no physical route required.
pub fn settings(
    name: &str,
    address: (Ipv4Addr, u8),
    address_v6: Option<(Ipv6Addr, u8)>,
    mtu: u16,
) -> io::Result<WindowsTunSettings> {
    if !(8..=30).contains(&address.1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the virtual IPv4 prefix must be /8 to /30 on Windows",
        ));
    }
    let settings = WindowsTunSettings {
        adapter_name: name.to_owned(),
        ipv4: address,
        dns: unused_dns(address.0, address.1),
        ipv6: address_v6,
        dns6: None,
        block_outside_dns: false,
        mtu: u32::from(mtu),
        ring_capacity: RING_CAPACITY,
        routes: Some(Vec::new()),
        announce_dns: false,
        adapter_guid: Some(adapter_guid(name)),
        require_physical: false,
    };
    settings.validate()?;
    Ok(settings)
}

fn route(network: IpAddr, prefix: u8) -> CaptureRoute {
    match network {
        IpAddr::V4(address) => CaptureRoute::V4(address, prefix),
        IpAddr::V6(address) => CaptureRoute::V6(address, prefix),
    }
}

/// An open Wintun adapter. Dropping it deletes the adapter with its
/// addresses and routes.
pub struct Tun {
    adapter: Mutex<WindowsTun>,
    writer: WindowsTunWriter,
    packets: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    name: String,
}

impl Tun {
    /// Creates the adapter with `address`/`prefix` (and the IPv6 address if
    /// any) and the MTU. Windows adds the on-link routes of the virtual
    /// subnets with the addresses.
    pub fn create(
        name: &str,
        address: (Ipv4Addr, u8),
        address_v6: Option<(Ipv6Addr, u8)>,
        mtu: u16,
    ) -> io::Result<Self> {
        let settings = settings(name, address, address_v6, mtu)?;
        let mut adapter = WindowsTun::open(&settings, &default_wintun_dll_path()?)?;
        let (queue, packets) = mpsc::channel::<Vec<u8>>(QUEUE);
        adapter.start_reader(move |packet| {
            let _ = queue.try_send(packet.to_vec());
        })?;
        Ok(Self {
            writer: adapter.writer(),
            adapter: Mutex::new(adapter),
            packets: tokio::sync::Mutex::new(packets),
            name: name.to_owned(),
        })
    }

    /// The adapter's name (its alias in Windows).
    pub fn name(&self) -> &str {
        &self.name
    }

    fn change_routes(&self, change: impl FnOnce(&mut Vec<CaptureRoute>)) -> io::Result<()> {
        let mut adapter = self.adapter.lock().unwrap_or_else(PoisonError::into_inner);
        let mut routes = adapter.routes().to_vec();
        change(&mut routes);
        adapter.set_routes(&routes)
    }

    /// Routes `network`/`prefix` into the adapter.
    pub fn add_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        let wanted = route(network, prefix);
        self.change_routes(|routes| {
            if !routes.contains(&wanted) {
                routes.push(wanted);
            }
        })
    }

    /// Removes a route [`add_route`](Self::add_route) added.
    pub fn remove_route(&self, network: IpAddr, prefix: u8) -> io::Result<()> {
        let gone = route(network, prefix);
        self.change_routes(|routes| routes.retain(|route| *route != gone))
    }

    /// Reads one IP packet.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut packets = self.packets.lock().await;
        loop {
            let Some(packet) = packets.recv().await else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the adapter stopped",
                ));
            };
            // Longer than the buffer (larger than the MTU allows): dropped.
            if packet.len() <= buffer.len() {
                buffer[..packet.len()].copy_from_slice(&packet);
                return Ok(packet.len());
            }
        }
    }

    /// Writes one IP packet.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        if self.writer.write(packet) {
            Ok(packet.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the adapter did not take the packet",
            ))
        }
    }
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
    fn each_name_keeps_its_own_guid() {
        assert_eq!(adapter_guid("anixmesh0"), adapter_guid("anixmesh0"));
        assert_ne!(adapter_guid("anixmesh0"), adapter_guid("anixmesh1"));
        let bytes = adapter_guid("anixmesh0").to_be_bytes();
        assert_eq!(bytes[6] >> 4, 5);
        assert_eq!(bytes[8] >> 6, 0b10);
    }

    #[test]
    fn the_settings_carry_only_the_mesh() {
        let settings = settings(
            "anixmesh0",
            (Ipv4Addr::new(10, 144, 0, 5), 24),
            Some(("fd00::5".parse().unwrap(), 64)),
            1380,
        )
        .expect("valid");
        assert_eq!(settings.routes, Some(Vec::new()));
        assert!(!settings.announce_dns);
        assert!(!settings.block_outside_dns);
        assert!(!settings.require_physical);
        assert_eq!(settings.adapter_guid, Some(adapter_guid("anixmesh0")));
        assert_eq!(settings.dns, Ipv4Addr::new(10, 144, 0, 254));
        assert_eq!(settings.mtu, 1380);
        // A prefix Windows adapters cannot take here is refused up front.
        assert!(settings_with_prefix(31).is_err());
        assert!(settings_with_prefix(7).is_err());
        assert!(settings_with_prefix(30).is_ok());
    }

    fn settings_with_prefix(prefix: u8) -> io::Result<WindowsTunSettings> {
        settings(
            "anixmesh0",
            (Ipv4Addr::new(10, 0, 0, 1), prefix),
            None,
            1380,
        )
    }

    #[test]
    fn the_unused_dns_address_is_never_ours() {
        assert_eq!(
            unused_dns(Ipv4Addr::new(10, 144, 0, 254), 24),
            Ipv4Addr::new(10, 144, 0, 253)
        );
        assert_eq!(
            unused_dns(Ipv4Addr::new(10, 0, 0, 1), 30),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(
            unused_dns(Ipv4Addr::new(10, 0, 0, 2), 30),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn routes_keep_their_family() {
        assert_eq!(
            route(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
            CaptureRoute::V4(Ipv4Addr::new(192, 168, 1, 0), 24)
        );
        assert_eq!(
            route("fd00::".parse().unwrap(), 64),
            CaptureRoute::V6("fd00::".parse().unwrap(), 64)
        );
    }
}
