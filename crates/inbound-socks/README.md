# inbound-socks

SOCKS5 server inbound for the node kernel (`"type": "socks"`), for devices
of the same internal network (mesh virtual addresses, a LAN) that send
traffic out through this node for a limited time.

```json
{"tag": "tmp-socks-7", "type": "socks", "listen": "10.126.126.1", "listen_port": 1080,
 "expires_at_ms": 1764045000000,
 "users": [{"name": "7", "username": "tmp-7", "password": "at-least-16-bytes"}]}
```

- Username and password (RFC 1929) are required; a user's login is
  `username`, or `name` when absent. Passwords are 16-255 bytes and an
  inbound needs at least one user.
- Only clients from internal addresses are answered: loopback,
  RFC 1918, `100.64.0.0/10`, link-local and IPv6 unique local.
- `CONNECT` only; `BIND` and `UDP ASSOCIATE` get "command not supported".
- The node runtime (`node-runtime`) only lets this type listen on an
  internal address (never `0.0.0.0` or `::`) and requires `expires_at_ms`
  at most seven days ahead; the inbound is removed at that time.
