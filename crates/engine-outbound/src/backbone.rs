//! Backbone links: point-to-point links between two border nodes of the
//! intranet mesh, carrying whole IP packets and the mesh's own control
//! messages.
//!
//! The mesh module chooses routes; a backbone link only moves packets between
//! its two ends and reports what it measures (round trip, loss, up/down). The
//! transport behind a link is provided by a [`BackboneFactory`] registered at
//! load time under a `kind` name; the open kernel ships no factory of its own
//! and never needs to know how a kind works. `params` is opaque to the kernel
//! and passed through to the factory.
//!
//! Contract shared by every implementation:
//!
//! * [`BackboneLink::try_send`] never blocks. A full queue, an oversized
//!   packet or a link that is down drops the packet and returns the reason.
//! * A link that loses its transport keeps existing: [`BackboneStats::up`]
//!   turns `false` and the implementation reconnects by itself.
//!   [`BackboneLink::recv`] only returns `None` after the link was closed by
//!   dropping it (or a fatal configuration error).
//! * [`PacketPolicy`] applies to [`BackbonePacket::Ip`] only: the receiving
//!   side checks the IP header, the source and destination prefixes and the
//!   rate before handing a packet out. The policy starts empty, which drops
//!   every IP packet (default deny). [`BackbonePacket::Control`] is passed
//!   through unchanged, subject to its own size cap and rate.
//! * Errors and stats never contain keys or other credentials.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use serde_json::Value;

use crate::BoxFuture;

/// One unit carried by a backbone link.
#[derive(Clone, PartialEq, Eq)]
pub enum BackbonePacket {
    /// A bare IPv4 or IPv6 packet (no mesh header, not encrypted by the mesh).
    Ip(Vec<u8>),
    /// A mesh control message (route summaries, probes), opaque to the link
    /// and delivered reliably and in order.
    Control(Vec<u8>),
}

impl BackbonePacket {
    pub fn len(&self) -> usize {
        match self {
            Self::Ip(p) | Self::Control(p) => p.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for BackbonePacket {
    // Contents are user traffic: only the kind and length are printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(p) => write!(f, "Ip({} bytes)", p.len()),
            Self::Control(p) => write!(f, "Control({} bytes)", p.len()),
        }
    }
}

/// Why [`BackboneLink::try_send`] dropped a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackboneSendError {
    /// Larger than [`BackboneLink::mtu`] (IP) or [`BackboneLink::max_control`].
    TooBig,
    /// The send queue is full.
    Full,
    /// The link has no working transport right now.
    Down,
    /// The link was closed.
    Closed,
}

impl fmt::Display for BackboneSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooBig => "backbone: packet too big",
            Self::Full => "backbone: send queue full",
            Self::Down => "backbone: link down",
            Self::Closed => "backbone: link closed",
        })
    }
}

impl std::error::Error for BackboneSendError {}

/// An IPv4 or IPv6 prefix (`addr/len`). Host bits of `addr` are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// `None` when `len` is longer than the address family allows.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (len <= max).then_some(Self { addr, len })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    /// A zero-length prefix (the whole address family).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl std::str::FromStr for IpPrefix {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const BAD: &str = "backbone: bad prefix";
        let (addr, len) = s.split_once('/').ok_or(BAD)?;
        let addr: IpAddr = addr.parse().map_err(|_| BAD)?;
        let len: u8 = len.parse().map_err(|_| BAD)?;
        Self::new(addr, len).ok_or(BAD)
    }
}

/// What the receiving end of a link accepts. Set by the mesh module from its
/// routing state (the peer's advertised subnets and virtual address, this
/// side's intranet prefixes) and replaced whenever that changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketPolicy {
    /// Source prefixes the peer may send from. Empty = drop every IP packet.
    pub src_allow: Vec<IpPrefix>,
    /// Destination prefixes the peer may send to. Empty = drop every IP packet.
    pub dst_allow: Vec<IpPrefix>,
    /// IP packets per second from the peer; 0 = the implementation's default.
    pub ip_pps: u32,
    /// IP bytes per second from the peer; 0 = the implementation's default.
    pub ip_bps: u64,
    /// Control messages per second from the peer; 0 = the implementation's default.
    pub control_pps: u32,
    /// Control bytes per second from the peer; 0 = the implementation's default.
    pub control_bps: u64,
}

impl PacketPolicy {
    /// Whether an IP packet from `src` to `dst` passes the prefix filter.
    pub fn allows(&self, src: IpAddr, dst: IpAddr) -> bool {
        self.src_allow.iter().any(|p| p.contains(src))
            && self.dst_allow.iter().any(|p| p.contains(dst))
    }
}

/// Dropped-packet counters, cumulative since the link was opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackboneDrops {
    /// Sent or received IP packets above the link MTU, control above its cap.
    pub too_big: u64,
    /// Send or receive queue full.
    pub queue_full: u64,
    /// Sent while the link was down.
    pub down: u64,
    /// Received IP packets with a malformed header.
    pub bad_packet: u64,
    /// Received IP packets outside [`PacketPolicy`] prefixes.
    pub policy: u64,
    /// Received packets over the [`PacketPolicy`] rates.
    pub rate: u64,
    /// IP packets lost while reassembling fragments inside the link
    /// (timeout, missing or inconsistent fragments).
    pub reassembly: u64,
}

/// What a link measures and counts. The mesh module uses `rtt_ms` and
/// `loss_ppm` as the inter-region cost and `last_change` for hysteresis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackboneStats {
    /// The link has a working transport.
    pub up: bool,
    /// The current transport session has forward secrecy (ephemeral key
    /// exchange per session). The mesh module sends no IP packets over a
    /// link where this is `false`.
    pub forward_secrecy: bool,
    /// When `up` last changed (or the link was opened).
    pub last_change: Option<SystemTime>,
    /// Short transport name for display (implementation-defined).
    pub transport: String,
    /// Current largest IP packet in either direction.
    pub mtu: usize,
    /// Smoothed round trip in milliseconds; `None` before the first sample.
    pub rtt_ms: Option<u32>,
    /// Packet loss over the implementation's window, in parts per million;
    /// `None` when the transport cannot measure it.
    pub loss_ppm: Option<u32>,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// IP packets split into fragments inside the link (sent).
    pub fragmented: u64,
    /// Times the transport was re-established.
    pub reconnects: u64,
    pub drops: BackboneDrops,
}

/// One backbone link. Dropping the last handle closes it.
pub trait BackboneLink: Send + Sync {
    /// Largest [`BackbonePacket::Ip`] accepted right now, in bytes.
    fn mtu(&self) -> usize;

    /// Largest [`BackbonePacket::Control`] accepted, in bytes.
    fn max_control(&self) -> usize;

    /// Queues one packet without blocking.
    fn try_send(&self, packet: BackbonePacket) -> Result<(), BackboneSendError>;

    /// Next packet from the peer that passed the policy; `None` once closed.
    fn recv(&self) -> BoxFuture<'_, Option<BackbonePacket>>;

    fn stats(&self) -> BackboneStats;

    /// Replaces the receive policy.
    fn set_policy(&self, policy: PacketPolicy);
}

/// A fixed, credential-free reason why a link could not be opened.
pub type BackboneOpenError = &'static str;

/// Opens backbone links of one kind.
pub trait BackboneFactory: Send + Sync {
    /// The `kind` name links of this factory are configured with.
    fn kind(&self) -> &'static str;

    /// Opens the link `id` with implementation-defined `params`. Returns once
    /// the configuration is accepted; connecting happens in the background
    /// and is visible through [`BackboneStats::up`].
    fn open(&self, id: &str, params: &Value) -> Result<Arc<dyn BackboneLink>, BackboneOpenError>;
}

fn factories() -> &'static Mutex<BTreeMap<&'static str, Arc<dyn BackboneFactory>>> {
    static FACTORIES: OnceLock<Mutex<BTreeMap<&'static str, Arc<dyn BackboneFactory>>>> =
        OnceLock::new();
    FACTORIES.get_or_init(Default::default)
}

/// Registers `factory` process-wide, replacing one with the same kind.
pub fn register_backbone_factory(factory: Arc<dyn BackboneFactory>) {
    factories()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(factory.kind(), factory);
}

/// The factory registered for `kind`.
pub fn backbone_factory(kind: &str) -> Option<Arc<dyn BackboneFactory>> {
    factories()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(kind)
        .cloned()
}

/// Registered kinds in sorted order.
pub fn backbone_kinds() -> Vec<&'static str> {
    factories()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_contains() {
        assert!(p("10.0.0.0/8").contains("10.255.1.2".parse().unwrap()));
        assert!(!p("10.0.0.0/8").contains("11.0.0.1".parse().unwrap()));
        assert!(p("10.1.2.3/32").contains("10.1.2.3".parse().unwrap()));
        assert!(!p("10.1.2.3/32").contains("10.1.2.4".parse().unwrap()));
        assert!(p("0.0.0.0/0").contains("8.8.8.8".parse().unwrap()));
        assert!(p("fc00::/7").contains("fd12::1".parse().unwrap()));
        assert!(!p("fc00::/7").contains("fe80::1".parse().unwrap()));
        assert!(p("::/0").contains("2001:db8::1".parse().unwrap()));
        // families never match each other
        assert!(!p("0.0.0.0/0").contains("::1".parse().unwrap()));
        assert!(!p("::/0").contains("10.0.0.1".parse().unwrap()));
        // host bits in the prefix are ignored
        assert!(p("10.1.2.3/16").contains("10.1.9.9".parse().unwrap()));
    }

    #[test]
    fn prefix_parse() {
        assert_eq!(p("192.168.0.0/16").to_string(), "192.168.0.0/16");
        assert!("10.0.0.0/33".parse::<IpPrefix>().is_err());
        assert!("::/129".parse::<IpPrefix>().is_err());
        assert!("10.0.0.0".parse::<IpPrefix>().is_err());
        assert!("x/8".parse::<IpPrefix>().is_err());
    }

    #[test]
    fn empty_policy_denies() {
        let policy = PacketPolicy::default();
        assert!(!policy.allows("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()));
        let policy = PacketPolicy {
            src_allow: vec![p("10.1.0.0/16")],
            dst_allow: vec![p("10.2.0.0/16")],
            ..Default::default()
        };
        assert!(policy.allows("10.1.0.5".parse().unwrap(), "10.2.3.4".parse().unwrap()));
        assert!(!policy.allows("10.3.0.5".parse().unwrap(), "10.2.3.4".parse().unwrap()));
        assert!(!policy.allows("10.1.0.5".parse().unwrap(), "10.3.3.4".parse().unwrap()));
    }

    #[test]
    fn debug_hides_contents() {
        assert_eq!(
            format!("{:?}", BackbonePacket::Ip(vec![1, 2, 3])),
            "Ip(3 bytes)"
        );
    }

    struct Nothing;
    impl BackboneFactory for Nothing {
        fn kind(&self) -> &'static str {
            "test-nothing"
        }
        fn open(
            &self,
            _id: &str,
            _params: &Value,
        ) -> Result<Arc<dyn BackboneLink>, BackboneOpenError> {
            Err("test: no links")
        }
    }

    #[test]
    fn registry() {
        register_backbone_factory(Arc::new(Nothing));
        assert!(backbone_kinds().contains(&"test-nothing"));
        let f = backbone_factory("test-nothing").unwrap();
        assert!(f.open("a", &Value::Null).is_err());
        assert!(backbone_factory("missing").is_none());
    }
}
