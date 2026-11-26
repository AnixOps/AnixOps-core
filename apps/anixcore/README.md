# anixcore

The AnixOps node kernel: protocol server inbounds (Shadowsocks-2022 and
Shadowsocks AEAD, Trojan,
VLESS with REALITY, VMess, Hysteria2, TUIC, Snell, AnyTLS, NaiveProxy) in one process, driven by
a local management API so that a node agent such as anix-agent can add and
remove inbounds and users and collect per-user traffic and online IPs.

```text
anixcore run -c config.json
anixcore run -c -              # the config on stdin: no file holds it
anixcore check -c config.json
anixcore version
```

```json
{
  "management": {"listen": "127.0.0.1:10085", "token": "change-me"},
  "inbounds": [
    {"tag": "ss", "type": "shadowsocks", "listen_port": 8388,
     "method": "2022-blake3-aes-128-gcm", "password": "<base64 key>",
     "users": [{"name": "1001", "password": "<base64 key>"}]}
  ]
}
```

The management API is plaintext HTTP with a bearer token that controls the
whole node, so `management.listen` must be a loopback address (`127.0.0.1`,
`::1`): `anixcore run` and `anixcore check` refuse any other address,
`0.0.0.0` and `::` included. Manage a node from another host through SSH or
a VPN that ends on its loopback. `"insecure_public": true` accepts a
non-loopback address in plaintext for a deployment that keeps the port on a
restricted network; `anixcore` then prints a warning at start. An empty
token is refused.

On Linux `anixcore` also runs the intranet mesh networks a node agent
sends with `PUT /v1/mesh` (`docs/architecture/mesh-status.md`), one
virtual interface each. It keeps this device's instance ID and the
networks' static keys in `"mesh_state_dir"` (default
`/var/lib/anixcore/mesh`); if that directory cannot be created the mesh is
left out and `GET /v1/status` does not list `mesh`.

External network bridges of those networks (spec §15.12) stay off unless
the config sets `"mesh_external_bridge": true`. Off, `anixcore` never runs
`nft` or touches conntrack, except to remove, under the host lock, the
bridge tables a node program left on this host (marked by
`/run/anixops-mesh-bridge-active` while a bridge may be installed).

The inter-region backbone of those networks (a border node's top-level
`backbone` section) stays off unless the config sets
`"mesh_backbone": true`. Off, `GET /v1/status` does not list
`mesh_backbone` and a `PUT /v1/mesh` body carrying a `backbone` section is
refused as a whole with 400 (`backbone_disabled`), leaving the running
networks as they are.

Custom paths of those networks (`routing.paths`) likewise stay off unless
the config sets `"mesh_paths": true`. Off, `GET /v1/status` does not list
`mesh_paths` and a `PUT /v1/mesh` body whose networks carry
`routing.paths` or `node.waypoint_relay: true` is refused as a whole with
400 (`paths_disabled`), leaving the running networks as they are. The
standalone `anixops-mesh run` does not follow this switch: it applies its
config file as written.

Regions (the top-level `region` object: the region measurement and a
border node's probe responder) stay off unless the config sets
`"mesh_regions": true`. Off, `GET /v1/status` does not list
`mesh_region_probe`, a `PUT /v1/mesh` body carrying `region` (even `null`)
is refused as a whole with 400 (`regions_disabled`), leaving the running
networks as they are, and `region_probe` is always `null`.

Users may carry `"speed_limit"` (Mbit/s for each direction, shared by all
of the user's connections) and `"device_limit"` (most client IPs online at
once); both default to 0, no limit.

An inbound behind a relay or load balancer that sends the PROXY protocol
takes `"accept_proxy_protocol": true`: its TCP connections must start with
a version 1 or 2 header, and the client address for device limits and
online IPs is the one in it. Only that relay may reach such a port.

Clients may multiplex their connections with sing-mux (sing-box
`multiplex`, mihomo `smux`) using the `smux`, `yamux` or `h2mux` protocol,
with or without `padding`, on VLESS, VMess, Trojan and Shadowsocks inbounds;
there is nothing to configure on the inbound, and a client that sets no
protocol (which makes it `h2mux`) is served too. TCP Brutal is not
supported.

VLESS, Trojan and AnyTLS inbounds send a connection that is not a user's to
their `"fallback"` (`{"server": "127.0.0.1", "server_port": 8080}`). With
`"fallbacks"` the destination depends on the connection, as in Xray:

```json
"fallbacks": [
  {"alpn": "h2", "dest": 8443, "xver": 1},
  {"path": "/ws", "dest": "127.0.0.1:8081"},
  {"name": "blog.example.com", "dest": "blog.internal:80"},
  {"dest": 8080}
]
```

`name` is the TLS server name, `alpn` the negotiated ALPN protocol and
`path` the path of an HTTP/1.x request; `dest` is `host:port` or a local
port, and `xver` 1 or 2 sends the destination a PROXY protocol header. The
entry with the most matching conditions takes the connection, and an entry
without conditions (or `fallback`) is the default.

A VLESS, VMess or Trojan inbound with the XHTTP transport and `h3` in its
TLS `alpn` serves XHTTP over HTTP/3 (QUIC) on the UDP port of the same
number, beside HTTP/2 and HTTP/1.1 on TCP, so both ports have to be open:

```json
{"tag": "vless-xhttp", "type": "vless", "listen_port": 443,
 "users": [{"name": "1001", "uuid": "<uuid>"}],
 "tls": {"certificate_path": "/etc/ssl/node.crt",
         "key_path": "/etc/ssl/node.key", "alpn": ["h3"]},
 "transport": {"type": "xhttp", "path": "/xh"}}
```

A Shadowsocks inbound with a `"shadow_tls"` object is served behind
ShadowTLS v3: clients make a real TLS 1.3 handshake with the `handshake`
site through the port, and everything that is not a ShadowTLS client is
relayed to that site.

```json
{"tag": "ss-stls", "type": "shadowsocks", "listen_port": 443,
 "method": "2022-blake3-aes-128-gcm", "password": "<base64 key>",
 "shadow_tls": {"users": [{"name": "1001", "password": "<password>"}],
                "handshake": {"server": "www.example.com", "server_port": 443},
                "strict_mode": true}}
```

With `users` in `shadow_tls` the inbound's users are the ShadowTLS users
(the Shadowsocks inbound then has none of its own, and its UDP port stays
closed); with `"password"` instead, all clients share that password and the
users are the Shadowsocks users. `strict_mode` serves clients only when the
site answered in TLS 1.3. The kernel lists `shadow_tls` in `GET /v1/status`
`features`.

A Shadowsocks inbound serves SIP003 plugin clients without a plugin
process: `"obfs": {"type": "http" | "tls", "host": "..."}` for simple-obfs
(`obfs-local`), and `"transport": {"type": "ws", "path": "/x"}` with or
without `"tls": {...}` for v2ray-plugin's `websocket` mode. v2ray-plugin
clients multiplex by default, which is not served: set `mux=0` (mihomo
`mux: false`). UDP is not part of either plugin and stays plain Shadowsocks
on the port. Neither plugin layer combines with `shadow_tls`.

A `naive` inbound serves NaiveProxy clients (and sing-box's `naive`
outbound): HTTP/2 `CONNECT` inside TLS with Basic proxy authentication and
the payload padding, TCP only.

```json
{"tag": "naive", "type": "naive", "listen_port": 443,
 "users": [{"name": "1001", "username": "alice", "password": "..."}],
 "tls": {"certificate_path": "/etc/ssl/site.crt", "key_path": "/etc/ssl/site.key"},
 "fallback": {"server": "127.0.0.1", "server_port": 8080}}
```

A client logs in with the user's `username` (its `name` without one) and
`password`. Whatever is not such a client's request is answered by the
`fallback` web server, which has to take HTTP/1.1 and cleartext HTTP/2 on
its port; without a fallback such connections and requests are held and
then dropped. See `crates/inbound-naive/README.md`.

The config format is documented in `crates/node-runtime/src/config.rs` and
the API in `crates/node-runtime/src/api.rs`. Users relay through a direct
outbound that refuses loopback and private targets unless
`"allow_private_targets": true`.

Domain egress routes from the panel (anix-control 「转发 → 分流」) are applied
with `PUT /v1/egress` (or the config member `egress`): the route's domains
leave through the exit node's Shadowsocks-2022 or VLESS relay, for every inbound, and
an exit node serves the relays. See `crates/node-runtime/src/egress.rs`.

The network model's device plan (anix-control `docs/design/network-model`)
is applied with `PUT /v1/network` (or the config member `network`): every
egress becomes an outbound `egress:<id>` bound to its source address and
health-checked from it, and an inbound with `"ingress": "<id>"` leaves
through that ingress's active path, failing over between egresses. See
`crates/node-runtime/src/network.rs`.

The panel's block rules are applied with `PUT /v1/rules`
(`{"block_domains": [..], "block_protocols": [..]}`): a connection to a
blocked domain (egress route matchers) or whose first bytes are a blocked
protocol (`bittorrent`, `http`, `tls`) is refused on every inbound. The
kernel lists `block_rules` in `GET /v1/status` `features`.

Port forwarding rules from the panel (anix-control 「转发」) are `forward`
inbounds: the listen port relays TCP and UDP to one fixed target, through
the inbound's base outbound only (egress routes do not apply). The target
may be private; it is the operator's, not a user's.

```json
{"tag": "rule-7", "type": "forward", "listen_port": 10001,
 "server": "203.0.113.7", "server_port": 443, "network": "tcp,udp",
 "outbound": "anx-line:7"}
```

`network` is `tcp`, `udp` or `tcp,udp` (the default). A forward has no
users; `GET /v1/inbounds/{tag}/traffic?reset=true` answers its bytes in
`inbound` (`{"up", "down"}` since the last reset), and every inbound reports
the same. `outbound` names a base outbound the binary registered, such as
`anx-line:<link_id>` on anx-node; plain anixcore only has `direct`.
