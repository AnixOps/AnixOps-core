# engine-outbound

`engine-outbound` holds the pluggable outbound interfaces shared by the
embedded engine (`engine-embedded`, iOS/macOS Network Extension) and the
protocol crates that plug into it (Shadowsocks-2022, VLESS + REALITY, and
later WireGuard and private protocols).

It contains interfaces only, plus the default `TcpDialer`:

- `TargetAddr`: IP socket address or domain plus port, with `port()`,
  `host()` and `From<SocketAddr>`.
- `ProxyStream` / `BoxStream`: a `Send + Unpin` tokio `AsyncRead + AsyncWrite`
  stream, type-erased.
- `Dialer`: opens the transport connection to a proxy server. Outbounds receive
  an `Arc<dyn Dialer>` when they are constructed, so the Network Extension can
  inject a dialer bound to the physical interface.
- `TcpOutbound`: `protocol()` tag, `connect(&TargetAddr)` and
  `open_udp(&TargetAddr)`, which returns a `UdpFlow` (a `DatagramSend` and a
  `DatagramRecv` half) to one destination. Protocols without UDP keep the
  default `open_udp`, which fails with `ErrorKind::Unsupported`.
  `UdpFlow::message_stream` adapts a stream that carries one datagram per
  write and read.
- `accept`: the shared accept step of TCP serve loops (`inbound-mixed`,
  `engine-inbound`, the node management API). Errors of one connection
  (`ECONNABORTED`, `WSAECONNRESET`) are skipped, resource errors (`EMFILE`,
  `ENFILE`, `ENOBUFS`, `ENOMEM`, unknown) pause 50 ms doubling to 1 s, and
  only an unusable listener (`EINVAL`, `EBADF`, `ENOTSOCK`) ends the loop.

- `happy_eyeballs`: connecting to a host with several addresses (RFC 8305).
  `TcpDialer` (`protect::connect_tcp_host`) resolves the server, interleaves
  the IPv6 and IPv4 addresses (the family that last connected to the host
  first) and starts the next attempt 250 ms after the previous one while that
  keeps running, at most four at a time; the first connection wins and the
  others are dropped. QUIC (`transport-quic`) tries the addresses one at a time,
  3 s each, the last with the rest of the 10 s handshake timeout. UDP without a
  handshake (`Dialer::open_datagram`, the direct outbound) takes the first
  address in the same order. The last address never has a limit of its own;
  the caller's connect timeout bounds the whole. Families are remembered per
  host and transport (`Transport::Tcp` / `Transport::Udp`), since IPv6 TCP can
  work where IPv6 UDP is dropped: QUIC and UDP flows use the UDP entry and fall
  back to the TCP one, and a TCP success never overrides what QUIC learned.
  When the table (1024 entries) is full, expired entries go first, then the
  oldest. Remembered families are forgotten when the path changes
  (`protect::path_generation`) and on `Dispatcher::reset_sessions`.
- `uri_host`: an IPv6 literal in brackets for URI authorities and `Host`
  headers (gRPC, WebSocket, XHTTP).
- UDP flows over a connected socket (`UdpFlow::connected_socket`) keep no
  receive buffer while idle: each datagram is read into a per-thread 64 KiB
  scratch buffer and copied out at its length. `UdpFlow::message_stream`
  allocates its read buffer per datagram (not zeroed).

Errors are `std::io::Error`; implementations must not put credentials in error
messages.
