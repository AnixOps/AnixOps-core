# netstack-smoltcp (vendored)

Userspace TCP/IP stack used by `engine-embedded`'s packet tunnel (the iOS
Network Extension and other TUN clients). Vendored from
[netstack-smoltcp 0.2.4](https://github.com/cavivie/netstack-smoltcp)
(MIT OR Apache-2.0, see `LICENSE-MIT` and `LICENSE-APACHE`) so it can be
tuned for phones. The upstream examples and integration tests are not copied.

Changes against 0.2.4 are listed here; measure each one with the
`Tunnel perf` workflow (`crates/engine-embedded/examples/tunnel_bench.rs`).

- `tcp.rs`: with nothing scheduled the socket loop parks until notified (10 s
  backstop) instead of re-polling every 5 ms.
- `tcp.rs`: the staging buffers between a smoltcp socket and its `TcpStream`
  are at most 16 KiB instead of one window each.
- `tcp.rs`: a socket in TIME-WAIT is removed after 1 s instead of smoltcp's
  10 s, and `TcpStream::poll_shutdown` completes once the FIN is queued (as
  `shutdown(SHUT_WR)` does) instead of when the socket reaches CLOSED. Each
  short connection the tunnel closed first kept its relay and both socket
  windows for over 10 s: 600 in a burst peaked at ~88 MiB.
