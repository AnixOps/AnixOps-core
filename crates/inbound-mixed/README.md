# inbound-mixed

Local mixed inbound: SOCKS5 and HTTP proxy requests on one port, relayed through any `engine_outbound::TcpOutbound` (a single protocol outbound or a routed one). It replaces the `mixed` inbound that the desktop clients got from an external engine.

- SOCKS5 (RFC 1928) `CONNECT`, no auth or username/password (RFC 1929). `UDP ASSOCIATE` when `MixedSettings::udp` is set (off by default): a relay socket on the listener's address, one `ClientConnector::open_client_udp` flow per destination (at most 64), only datagrams from the client's IP and first source port, replies carry the destination the client asked for, fragments dropped, the association ends with the TCP connection. `BIND`, and `UDP ASSOCIATE` without `udp`, answer "command not supported".
- HTTP/1.x `CONNECT` tunnels and absolute-form plain requests, forwarded in origin form with `Connection: close`; optional `Proxy-Authorization: Basic`.
- The first byte picks the protocol. Request heads are capped at 16 KiB; handshake and connect timeouts and a connection cap come from `MixedSettings`. Counters in `MixedStats` carry no addresses or contents.
- The accept loop survives transient `accept` errors (`engine_outbound::accept`): a client that resets before it is accepted (`ECONNABORTED`, `WSAECONNRESET`) is skipped, and running out of file descriptors or buffers (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) pauses the loop 50 ms, doubling up to 1 s, instead of stopping the listener; both are counted in `MixedStats::accept_errors`. Only a listener that is no longer usable ends `serve`.

Bind it to loopback. `tests/mixed_proxy.rs` covers both protocols end to end; all verification runs in GitHub Actions.
