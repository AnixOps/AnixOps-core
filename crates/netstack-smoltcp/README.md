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
- `tcp.rs`: a socket in TIME-WAIT is removed after 100 ms instead of smoltcp's
  10 s, and `TcpStream::poll_shutdown` completes once the FIN is queued (as
  `shutdown(SHUT_WR)` does) instead of when the socket reaches CLOSED. Each
  short connection the tunnel closed first kept its relay and both socket
  windows for over 10 s: 600 in a burst peaked at ~88 MiB.
- `udp.rs`: a UDP packet whose header does not parse is dropped and counted,
  and the UDP socket reads the next one; upstream ended the socket's stream,
  so the first such packet stopped all UDP (DNS included) until the stack
  was rebuilt. A datagram that cannot be built into one IP packet (too large,
  or addresses of two families) is dropped and counted too instead of failing
  the write half, which ended the caller's reply loop.
- `reassembly.rs` (new): IPv4 and IPv6 fragments of a UDP datagram are held
  until it is whole and go on as one packet (at most 32 datagrams and
  256 KiB at once, 15 s each; overlapping fragments drop their datagram).
  Upstream passed IPv4 fragments to the UDP socket one by one, where the
  first of them ended it, and ignored IPv6 fragments. Fragments of other
  protocols are dropped, as smoltcp drops them.
- `packet.rs`: an IPv4 header shorter than 20 bytes is refused.
- `tcp.rs`: sockets are made by the socket loop, one per (app, destination)
  pair: a SYN the app sends again before the SYN-ACK (or of a connection the
  loop already has) reaches the socket that took the first one. Upstream
  made a socket and a `TcpStream` for every SYN, so each retransmitted SYN
  opened a second stream that never got data, and left a socket in LISTEN
  that took the next connection to the same destination from any source.
  A `TcpStream` goes out once its socket left LISTEN, with the endpoints
  smoltcp connected it to (a socket in LISTEN takes a SYN from any source);
  a socket smoltcp puts back into LISTEN (a RST in SYN-RECEIVED) is removed
  and its stream ends; a socket whose SYN smoltcp refused is removed after
  2 s once no frame is queued.
- `tcp.rs`: `TcpStream::abort` and `TcpAbortHandle` reset the connection
  (smoltcp sends a RST), where dropping the stream closes it with a FIN.
  After the stream is dropped the socket discards what the app still sends,
  so the window stays open and the app's FIN arrives (upstream kept the
  bytes until the window was zero, and the socket stayed until the app gave
  up), and is reset 60 s after the drop if it is still open.
- `stats.rs` (new): `StackStats` counts what the above drop or rebuild;
  `StackBuilder::stats` shares one set with the caller.
