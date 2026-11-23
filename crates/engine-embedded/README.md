# engine-embedded

In-process engine for the iOS Network Extension (roadmap M1a). It never starts a process and never touches Apple SDK objects; the Swift packet tunnel talks to it only through the C ABI.

- `ffi`: `networkcore_ios_*` C ABI, mirrored by `include/networkcore_ios_runtime.h`. Every symbol catches panics and returns a stable code that maps onto `platform.ios.embedded_runtime.*` diagnostics, following `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`.
- `EmbeddedRuntime`: parses and validates the JSON config envelope (`schema_version` 1), builds the outbound, owns the tunnel lifecycle and reports a sanitized status (profile id, state, counters; no addresses, keys or traffic).
- `tunnel`: one current-thread tokio runtime on a dedicated thread. Packets from `packetFlow` enter through `input_packet`; packets for `packetFlow` leave through the writer callback. TCP flows go through the outbound; UDP/53 is re-sent as DNS-over-TCP through the outbound; other UDP goes through the outbound's `open_udp`, one flow per app socket and destination (at most `limits.max_udp_flows`: 256 on iOS, 4096 elsewhere; closed after 60 s without traffic). A full flow table makes room for a new flow by closing flows idle for 15 s or more, longest idle first, or else the least active flow (idle for 2 s or more) of an app socket holding more than a quarter of the table; only then is the new flow's datagram dropped (`udp_evicted`, `udp_dropped`). TCP connections are capped by `limits.max_tcp_connections` (128 on iOS, 512 on Android, 1024 on desktop); at the cap a new connection replaces the one without payload longest if that has been idle for 30 s or more (`tcp_evicted`), and is refused only when all are active (`tcp_rejected`). An outbound without UDP drops those datagrams, so QUIC falls back to TCP. A UDP datagram that comes in IP fragments (IPv4 or IPv6) is joined before it goes on; a UDP packet that does not parse, a reply too large for one IP packet and fragments that never make a whole datagram are dropped while the rest keeps flowing, counted in the tunnel stats as `udp_malformed`, `udp_unsendable`, `ip_fragments_dropped` (joined ones in `udp_reassembled`). UDP currently works through `direct`, routing rules and groups, VMess, Hysteria2, TUIC, Snell, Trojan, VLESS, Shadowsocks (SIP004 and 2022) and SOCKS5. Each UDP flow has its own outbound socket (or proxy session) and takes replies only from its destination, so to the apps the tunnel is a symmetric NAT (endpoint-dependent mapping and filtering): a mapped port a STUN server reports is not reused toward other peers and peers cannot send first, so P2P apps (WebRTC, game consoles behind the macOS gateway mode) fall back to relays. A TCP flow that ends cleanly (both sides finished) closes with a FIN; one that fails (the outbound could not connect or broke, the idle timeout, closed from the connection list, `reset_network`, or closed to make room at the cap) and a connection refused at the cap are reset with a RST, so an app never takes a cut response as whole; `REJECT` answers keep closing normally. After the tunnel let go of a connection the userspace stack still sends what was written and discards what the app sends, and resets the connection 60 s later if it is still open. A SYN the app sends again before the SYN-ACK came opens no second connection. Ports other than the client-first ones (80, 443, 465, 853, 993, 995, 2053, 2083, 2087, 2096, 5223, 5228, 8080, 8443) wait 100 ms for the app's first bytes; a destination where the app stayed silent twice in a row (within 10 minutes) connects at once for 30 minutes (`tcp_first_wait_skipped`), without a sniffed host name, until `reset_network` forgets it.
- Outbounds implement `engine_outbound::TcpOutbound` and are built by the protocol registry (`engine_outbound::registry`) from the config `type`: `shadowsocks` (Shadowsocks-2022 and AEAD `aes-128-gcm`/`aes-256-gcm`/`chacha20-ietf-poly1305`, from `outbound-shadowsocks`), `vless` (VLESS over REALITY with optional XTLS Vision, or over TCP/standard TLS with an optional WebSocket, from `outbound-vless`), `vmess` (VMess AEAD over TCP/TLS/WebSocket, from `outbound-vmess`), `hysteria2` and `tuic` (TCP over QUIC, from `outbound-hysteria2` and `outbound-tuic`), `snell` (from `outbound-snell`), `mieru` (from `outbound-mieru`), `iwan` (from `outbound-iwan`), `trojan`, `socks`, `http` and `direct`. A new protocol plugs in without changing the tunnel.
- `wireguard`: a packet-level mode for one WireGuard peer. Packets skip the TCP/IP stack and are sealed with boringtun's Noise state machine (BSD-3-Clause, `device` feature off) into datagrams on one connected UDP socket; the extension's routes apply the peer's `AllowedIPs`. Buffers stay under 0.5 MiB.

## Protocol modules

Each protocol is its own crate behind a cargo feature; `src/protocols.rs` registers the enabled ones. The default build enables all of them.

| feature | config `type` | crate |
| --- | --- | --- |
| (always) | `direct` | this crate |
| `http` | `http` (HTTP CONNECT proxy, optional TLS and Basic auth) | `outbound-http` |
| `hysteria2` | `hysteria2` (QUIC + HTTP/3 password auth, TCP streams; optional `"obfs": {"type": "salamander", "password": ...}`; no port hopping yet) | `outbound-hysteria2` (QUIC from `transport-quic`) |
| `iwan` | `iwan` (Panabit iWAN layer-3 tunnel as a routable node: `server`, `port`, `username`, `password`, `mtu`, `encrypt`, `pipe_id`, `pipe_idx`, optional `dns`, `tcp_buffer_bytes`; TCP and UDP through a per-node userspace stack whose address comes from the server; IPv4 only, no encryption, see spec §9) | `outbound-iwan` (clean-room from `docs/protocols/iwan.md`) |
| `mieru` | `mieru` (Mieru over TCP, `username`, `password`, optional `port_range` `low-high`; one session per connection, no UDP transport, multiplexing or low entropy segments yet) | `outbound-mieru` (clean-room from `docs/protocols/mieru.md`) |
| `shadowsocks` | `shadowsocks` (`method` `2022-blake3-*` or an AEAD method) | `outbound-shadowsocks` |
| `snell` | `snell` (Snell v1–v4 and v6, `psk`, `version`, v6 `mode` `default`/`unshaped`/`unsafe-raw`, `obfs` `http` for v1–v4, `reuse`, `userkey`; TCP, UDP over TCP in the crate API) | `outbound-snell` (clean-room from `docs/protocols/snell.md`) |
| `socks` | `socks` (SOCKS5, optional username/password) | `outbound-socks` |
| `tuic` | `tuic` (TUIC v5: UUID + password, `congestion_control` `cubic`/`new_reno`/`bbr`; TCP only) | `outbound-tuic` (QUIC from `transport-quic`) |
| `trojan` | `trojan` (TCP, or `"transport": {"type": "ws"}` / `{"type": "grpc", "service_name": ...}`) | `outbound-trojan` (TLS from `transport-tls`, WebSocket from `transport-ws`, gRPC from `transport-grpc`) |
| `vless` | `vless` (`reality`, or `tls` and/or `"transport": {"type": "ws"}` / `{"type": "grpc"}`) | `outbound-vless` |
| `vmess` | `vmess` (AEAD, alterId 0; `security` `auto`/`aes-128-gcm`/`chacha20-poly1305`; optional `tls` and `"transport": {"type": "ws"}` / `{"type": "grpc"}`) | `outbound-vmess` |
| `wireguard` | `wireguard` (a single `outbound` runs as the whole-device tunnel below; in `routing.outbounds` it is a routable node: `server`, `port`, `private_key`, `peer_public_key`, optional `preshared_key`, `local_address` (required), `allowed_ips` (default everything; destinations and received sources outside it are refused/dropped), `dns` (inside the tunnel, else the system resolver), `mtu`, `persistent_keepalive_secs`, `reserved`, `tcp_buffer_bytes` (both directions; when absent the receive buffer is 512 KiB on desktop systems, 256 KiB on Android and 64 KiB on iOS, the send buffer 64 KiB); TCP and UDP through a per-node userspace stack, IPv4 and IPv6) | this crate + boringtun; `outbound-wireguard` for routed nodes |
| `local-proxy` | (desktop mode, not a protocol) | `inbound-mixed` |

`cargo build -p engine-embedded --no-default-features --features vless` builds a runtime with only VLESS and direct; any other `type` is rejected with `config_rejected`. To add a protocol: create an `outbound-<name>` crate that implements `TcpOutbound` and `engine_outbound::registry::OutboundFactory`, add it as an optional dependency with a feature here, and register its factory in `protocols::default_registry`. `EmbeddedRuntime::with_registry` accepts a caller-built registry, for protocol crates kept outside this repository. The CI job `Protocol feature matrix` builds, lints and runs the C ABI contract tests with each feature alone.

## Server certificates

The TLS and QUIC clients of the outbounds (`trojan`; `vless` and `vmess` with `tls`; `http` with `"tls": true`; `hysteria2`; `tuic`; XHTTP over HTTP/3) check the server certificate in `transport-tls`:

- By default the chain must lead to a WebPKI root and name the server (`server_name`, else `server`).
- `pinned_certificate_sha256` (SHA-256 of the whole leaf certificate, DER) and `pinned_public_key_sha256` (SHA-256 of its SubjectPublicKeyInfo, DER) are lists of 64 hex digits, either case, `:` or `-` between the bytes allowed. With pins the leaf certificate must match one pin of either list: on top of WebPKI, or in its place with `insecure`, which is how a self-signed server is pinned. Only the leaf counts, never the rest of the chain. The lists sit next to `insecure`: at the top level of `trojan`, `hysteria2`, `tuic` and `http` (where pins without `tls` fail the build), inside `tls` for `vless` and `vmess`. A value that is not a SHA-256 digest fails the build with `<type> certificate pins are invalid`.
- `insecure` without a pin accepts any certificate; only the handshake signature is still checked. Anyone on the path can then stand in for the server and read what the protocol sends, credentials included, so building such a client logs a `tracing` warning with the server name, once per name per process.
- REALITY (`vless` with `reality`) authenticates the server with its own key and takes no pins.

`node-import` fills the lists from subscription pins: share-link `pinSHA256` and `pcs`, sing-box `certificate_sha256` and `certificate_public_key_sha256`, Clash `fingerprint`, Surge `server-cert-fingerprint-sha256`, Loon and Quantumult X `tls-cert-sha256` and `tls-pubkey-sha256`. A node whose pin is not a SHA-256 digest is reported unsupported instead of running without it.

## Proxy chains (`via`)

An outbound may set `via`: the id of another node in `routing.outbounds` (nodes naming the same one share it, for example one iWAN session) or an inline outbound object (the only form a single `outbound` takes). Its TCP connections and its datagrams to the server then go through that outbound (`engine_outbound::OutboundDialer`). Chains are at most 4 outbounds long and loops are rejected. Protocols that open their own sockets (`hysteria2`, `tuic`, `iwan`) cannot use a `via`. See `docs/architecture/outbound-via.md`; `tests/via_chain.rs` runs a Shadowsocks-2022 node through an in-process iWAN line.

## Desktop local proxy

`local_proxy::LocalProxy::start(config, listen, settings)` takes the same config envelope and serves its outbound (single or `routing`) behind a SOCKS5/HTTP mixed listener from `inbound-mixed`, on its own thread and tokio runtime. Because applications hand the proxy a host name, domain rules match without FakeIP. WireGuard is a packet tunnel and is rejected in this mode. Bind it to loopback; `tests/local_proxy.rs` covers direct, routed and failure cases.

`routing.rule_sets` carries named lists for `RULE-SET,<name>,<target>` rules: `{"china": {"domain_suffix": [...], "ip_cidr": [...]}}`, up to 16 sets and 500,000 entries in all. A set is one rule, matched by a hash lookup per domain suffix and a binary search over merged networks, so a list the size of the mainland China domains costs the same per connection as a short one. Its networks match only a destination that is already an address; a domain is never resolved for them. A rule naming a set the envelope does not carry is rejected.

A set with a `url` is downloaded by the engine itself (`local-proxy` feature) and refreshed every `interval_secs`. With `routing.rule_set_cache_dir`, an absolute directory the client owns, every download that passed its checks is also kept there (written to a temporary file, synced, then renamed), so after a restart the set starts with its last good download instead of empty, keeps it while downloads fail, and is downloaded again an interval after it. Copies are read back only when their digest and, for a signed set, their signature still verify; see `src/rule_set_cache.rs` and `docs/architecture/routing-policy-group-model.md`.

## HTTPS decryption (MITM)

The default `mitm` feature lets the packet tunnel decrypt HTTPS for host names listed in a plugin's `[MITM]` section. Add an optional `mitm` object to the config envelope:

| Field | Meaning |
| --- | --- |
| `policy` | Optional plugin text (`[URL Rewrite]`, `[Header Rewrite]`, `[Map Local]`, `[MITM]`) evaluated by the same rewrite engine as the desktop proxy (`engine-native` hook plus the `mitm-policy` core). |
| `plugins` | Optional Loon plugin texts. Each is imported with `mitm_policy::loon_plugin` and merged with `policy` into one policy (`merged_plugin_source`): rewrite sections keep plugin order and `[MITM]` hostname lists are combined, with an excluded host staying excluded. A plugin the policy core refuses is left out; `[Rule]` lines are not applied here. |
| `ca_certificate` | Base64 DER of the device root that the iOS app generates and the user trusts. |
| `ca_private_key` | Base64 X9.63 P-256 private key (`04 ‖ X ‖ Y ‖ D`), as `SecKeyCopyExternalRepresentation` returns it. |
| `script_assets` | Optional map of `[Script]` URL (`script-path`) to the local file holding the copy the user consented to. Needs the default `scripts` feature; every file must exist at start and is pinned by SHA-256. |
| `resource_assets` | Optional map of a remote `[Map Local]` `data` URL (or Quantumult X `echo-response` file) to the local file the app downloaded it to. Read once at start (each at most 256 KiB, 2 MiB in all) and inlined into the plugin; `mitm_policy::loon_plugin` lists the URLs a plugin needs in `remote_resources`. A line whose file is absent is left out. |
| `script_store_path` | Optional JSON file for `$persistentStore` (in memory when absent). A file that is not a JSON object of strings never stops the runtime: it is moved to `<path>.corrupt` (the latest copy only) and the store starts empty. Writes go to a temporary file that is flushed and renamed over the store. |

TCP flows to port 443 whose ClientHello SNI matches the hostname list are terminated with a per-host leaf signed by that root, re-encrypted to the origin through the configured outbound, and parsed as HTTP/1.1 so rewrite rules can reject, redirect, rewrite headers or answer locally. Only `http/1.1` is offered over ALPN. Requests whose response a rule reads ask for `Accept-Encoding: identity`, and a body the origin compresses anyway (gzip, deflate, br, zstd) is decoded before the rules see it (`src/capture/decode.rs`, which also decodes HAR exports, redaction and `networkcore_ios_decode_body`); bodies over 1 MiB, server-sent events and protocol upgrades are relayed unchanged (a body rule they match is skipped and the capture row says `rules_skipped`). With capture on, an exchange is listed from its request head (`capture_requests` with `since_rev` shows it `in_progress`), and an event stream's events, or a WebSocket's messages after a `101` (RFC 6455, `permessage-deflate` inflated for the view, bytes relayed unchanged; `src/capture/websocket.rs`), are kept as they are relayed, at most 512 / 64 KiB per exchange (`src/capture/stream.rs`, `capture_exchange`). A decrypted HTTP/2 connection also keeps its last 512 frame headers on both links (`src/capture/h2frames.rs`, `capture_h2_frames`). Other flows are untouched. QUIC (UDP/443) whose first Initial packets name a host on the list (or whose Fake-IP name is on it) is refused with ICMP port unreachable, so the app falls back to TCP and is decrypted there; other QUIC is untouched. Tunnel stats count `mitm_flows`, `mitm_failed` and `quic_mitm_fallback`. With `scripts`, `[Script]` dispatches run in QuickJS on the blocking pool (8 MiB heap, at most 3 s); their `$httpClient` / `$task.fetch` requests open one HTTP/1.1 connection each through the tunnel's dispatcher, so they follow the same routing, with answers up to 1 MiB; redirects are followed (at most 5 hops within the request's one timeout; a 303, or a 301/302 answering a POST, becomes a GET; `Authorization`, `Cookie` and a script-set `Host` go only to the same origin) unless the script sets `auto-redirect: false` or `opts.redirection: false`, and `binary-mode` answers keep every byte. A script never stalls the tunnel thread; rquickjs ships no iOS bindings, so iOS builds generate them with bindgen against the SDK set in `BINDGEN_EXTRA_CLANG_ARGS_<target>` (see `.github/scripts/build-ios-runtime-xcframework.sh`). A build without the feature rejects a config that has a `mitm` section. `tests/mitm.rs` runs a client, the engine and a TLS origin over in-memory streams.

## Config envelope



```json
{
  "schema_version": 1,
  "profile_id": "node-1",
  "mtu": 1500,
  "outbound": {
    "type": "shadowsocks",
    "server": "example.com",
    "port": 8388,
    "method": "2022-blake3-aes-128-gcm",
    "password": "<base64 PSK>"
  },
  "dns": { "upstream": "1.1.1.1:53", "timeout_ms": 5000 },
  "limits": {
    "max_tcp_connections": 128,
    "max_udp_flows": 256,
    "max_dns_in_flight": 32,
    "tcp_window_bytes": 65536,
    "idle_timeout_secs": 300,
    "connect_timeout_secs": 10
  }
}
```

A VLESS + REALITY outbound uses the same envelope with:

```json
"outbound": {
  "type": "vless",
  "server": "example.com",
  "port": 443,
  "uuid": "<uuid>",
  "flow": "xtls-rprx-vision",
  "reality": {
    "server_name": "www.example.com",
    "public_key": "<pbk>",
    "short_id": "<sid>",
    "fingerprint": "chrome"
  }
}
```

`flow` may be empty for plain VLESS; `short_id` defaults to empty and `fingerprint` to `auto` (Safari's ClientHello on iOS and macOS, Chrome's elsewhere; `chrome`, `safari` and `chrome-nopq`, which drops the post-quantum key share, name one explicitly). The uuid, like the Shadowsocks password, comes from the Keychain and never appears in status.

A WireGuard envelope replaces `outbound` with the fields of one `wg-quick` peer (keys are standard base64; `preshared_key` and `persistent_keepalive_secs` are optional, `dns` and `limits` are ignored):

```json
"outbound": {
  "type": "wireguard",
  "private_key": "<base64>",
  "peer_public_key": "<base64>",
  "preshared_key": "<base64>",
  "server": "vpn.example.com",
  "port": 51820,
  "persistent_keepalive_secs": 25
}
```

`dns` and `limits` are optional. `dns` may also list named `servers` (`tcp://`, DNS over TLS `tls://`, DNS over HTTPS `https://`, each `via` the proxy or `direct`), `hosts` answered locally and per-domain `rules`; see [docs/architecture/embedded-dns.md](../../docs/architecture/embedded-dns.md). `max_tcp_connections` and `max_udp_flows` default per platform (the example shows the iOS values). On iOS the defaults keep the worst case near 128 flows × (2 × 64 KiB window + relay and cipher buffers), about 25 MiB, inside the roughly 50 MiB Network Extension limit; desktop (1024) and Android (512) allow more, up to roughly 200 MiB and 100 MiB in the worst case, where no such limit applies. Each relayed connection or flow holds at least one file descriptor (a system-proxy connection two), so on Linux, Android, macOS and iOS the runtime raises the process's soft `RLIMIT_NOFILE` to the hard limit once (on Apple platforms at most `kern.maxfilesperproc`) and then lowers both caps, configured or default, to fit it: a quarter of the descriptors (64 to 512) stays reserved for DNS, rule sets, health checks and listeners, TCP gets at most half of the rest and UDP what TCP leaves. With a hard limit of 1024 that is 384 TCP connections and 384 UDP flows, so idle connections make room before descriptors run out. Windows keeps the configured caps. Real peak memory is measured on an iPhone during M1 acceptance.

Tests: `crates/outbound-shadowsocks/tests/shadowsocks_interop.rs` and `aead_interop.rs` check the Shadowsocks-2022 and AEAD clients against the shadowsocks-rust server (Unix only, dev-dependency), `tests/tunnel_packets.rs` drives raw IP packets through the stack, `tests/wireguard_packets.rs` round-trips packets through an in-process boringtun peer, and `tests/ffi_contracts.rs` exercises the C ABI. All verification runs in GitHub Actions.
