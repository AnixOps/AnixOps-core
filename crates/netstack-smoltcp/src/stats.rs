//! Counters of the packets the stack drops or rebuilds instead of passing
//! them on as they came.

use std::sync::atomic::{AtomicU64, Ordering};

/// What the stack dropped or rebuilt. One set is shared by a
/// [`Stack`](crate::Stack) and its [`UdpSocket`](crate::UdpSocket); hand one
/// in with [`StackBuilder::stats`](crate::StackBuilder::stats) to read it.
/// The counters hold no addresses and no payloads.
#[derive(Debug, Default)]
pub struct StackStats {
    udp_malformed: AtomicU64,
    udp_unsendable: AtomicU64,
    ip_fragments_dropped: AtomicU64,
    udp_reassembled: AtomicU64,
}

impl StackStats {
    /// UDP packets from the TUN side whose UDP header did not parse (cut
    /// short, or a length field that disagrees with the packet). Each one is
    /// dropped; the UDP socket goes on with the next packet.
    pub fn udp_malformed(&self) -> u64 {
        self.udp_malformed.load(Ordering::Relaxed)
    }

    /// UDP datagrams for the TUN side that could not be built into one IP
    /// packet (larger than an IP packet carries, or addresses of two
    /// families). Each one is dropped; the UDP socket goes on with the next.
    pub fn udp_unsendable(&self) -> u64 {
        self.udp_unsendable.load(Ordering::Relaxed)
    }

    /// IP fragments dropped instead of joined: fragments of any protocol but
    /// UDP (or of UDP while the stack passes no UDP on), malformed ones,
    /// copies of one already held, and every fragment of a UDP datagram that
    /// overlapped or disagreed about its end, still missed a fragment 15 s
    /// after its first one came, made room for newer datagrams while too
    /// many were held, or came out larger than one IP packet.
    pub fn ip_fragments_dropped(&self) -> u64 {
        self.ip_fragments_dropped.load(Ordering::Relaxed)
    }

    /// UDP datagrams rebuilt from IP fragments.
    pub fn udp_reassembled(&self) -> u64 {
        self.udp_reassembled.load(Ordering::Relaxed)
    }

    pub(crate) fn count_udp_malformed(&self) {
        self.udp_malformed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_udp_unsendable(&self) {
        self.udp_unsendable.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_ip_fragments_dropped(&self, fragments: usize) {
        self.ip_fragments_dropped
            .fetch_add(fragments as u64, Ordering::Relaxed);
    }

    pub(crate) fn count_udp_reassembled(&self) {
        self.udp_reassembled.fetch_add(1, Ordering::Relaxed);
    }
}
