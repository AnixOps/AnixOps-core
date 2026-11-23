# tls-mimic

`tls-mimic` produces browser-shaped TLS 1.3 ClientHello messages (a uTLS-like
fingerprint layer) and runs a minimal TLS 1.3 client on top of them. It is the
shared fingerprint module for REALITY and any later protocol that needs to look
like a browser on the wire.

Fingerprints:

- `Fingerprint::Chrome` (default): desktop Chrome shape with GREASE cipher,
  group, version, signature scheme and extension values, per-connection
  permutation of all non-GREASE extensions, `X25519MLKEM768` + `X25519` key
  shares with an X25519 key each, ECH GREASE (`0xfe0d`, payload length drawn
  from 144, 176, 208 and 240, AES-128-GCM), ALPS on the new code
  point (`0x44cd`), brotli certificate compression offer, the `0xca34`
  extension Chrome 157 stable sends (as captured), and ALPN `h2`, `http/1.1`.
- `Fingerprint::ChromeNoPq`: the same without the post-quantum hybrid group
  and the ML-DSA signature schemes. No shipping browser sends it, so it has
  no capture to check against.
- `Fingerprint::Edge` (`edge`): desktop Edge 157, the Chrome shape without
  `0xca34`.
- `Fingerprint::Firefox` (`firefox`): desktop Firefox 160: no GREASE, a fixed
  extension order, `X25519MLKEM768` + `X25519` + `P-256` key shares (the
  hybrid share ends with the X25519 share's key, as Firefox sends it),
  delegated_credentials and record_size_limit, zlib/brotli/zstd certificate
  compression offer, ECH GREASE last with the payload as long as the
  ClientHelloInner Firefox pads (server name to 100 bytes, then RFC 9849
  rounding to a multiple of 32, plus the AEAD tag: 240 bytes for a first
  connection to a name of up to 100 bytes) and AES-128-GCM or
  ChaCha20-Poly1305 at random.
- `Fingerprint::FirefoxEsr` (`firefox-esr`): Firefox 153 ESR, the Firefox
  shape plus the `0xc00a` suite and the FFDHE groups; its ECH GREASE inner
  hello is rounded the older way (`31 - (L % 32)`), so the payload is 239
  bytes where Firefox 160 sends 240.
- `Fingerprint::Safari`: Safari and every other client of Apple's network
  stack (NSURLSession) on iOS and macOS, taken from Safari 26.6.2 on macOS
  26.7.2: its own cipher order (with the CBC and 3DES suites), a fixed
  extension order, `X25519MLKEM768` + `X25519` key shares with an X25519 key
  each, zlib certificate compression offer, no ALPS, no ECH GREASE, no session
  ticket extension.
  The iOS simulator's capture is checked against the same profile.

Every fingerprint is checked against its browser by JA4, JA3N (JA3 with the
extensions sorted), for browsers that do not permute extensions JA3
(`tls_mimic::ja`), and by whether the `X25519MLKEM768` share ends with the
`X25519` share's key (`Hello::hybrid_x25519`), which JA3 and JA4 do not see
but anyone who reads the ClientHello can compare. The ECH GREASE extension is
checked too: its AEAD and payload length must be ones the profile produces
for that ClientHello, and where nothing in the profile's ClientHello length is
drawn at random (Firefox, Safari) the whole length must equal the browser's.
The encapsulated key of every ECH GREASE extension is a fresh X25519 public
key (a canonical point on the curve, as browsers send it, never the key
share's key); random bytes would give a forgery away on three connections out
of four (`ja::is_x25519_public_key`).
`tests/browser_fingerprints.rs` compares the captures committed under
`tests/data/` on every test run;
`.github/workflows/browser-fingerprints.yml` captures current Chrome, Edge,
Firefox, Firefox ESR (Linux), Safari (`nscurl`) and the iOS simulator
(macOS) every week and on tls-mimic changes, fails when one moved, and prints
a profile derived from the capture (`ja::spec_from_hello`). To capture a
browser by hand: `cargo run -p tls-mimic --example fp_capture -- 127.0.0.1:8443
out.hex`, then point the browser at `https://<name>:8443/`.

`Fingerprint::platform_default()` (config name `auto`) is Safari on Apple
platforms and Chrome elsewhere: a Chrome ClientHello from a device whose
TCP/IP stack is Apple's is unusual, and on iOS it is the largest class of
client.

Fingerprints are data. Each built-in one is a JSON file under `fingerprints/`
(format in `src/profile.rs`: cipher suites, the ordered extension list with
its parameters, `"grease"` placeholders, whether extensions are permuted,
BoringSSL-style `padding`, `raw` for an extension with a fixed body that
this crate has no name for, and on `key_share` whether the `X25519MLKEM768`
share reuses the `X25519` share's key: `"hybrid_x25519": "shared"` as in
Firefox, or the default `"separate"`, a key of its own, as in Chrome, Edge
and Safari; and on `ech_grease` the payload length rule and the AEADs:
`"payload_lengths"` drawn per connection, or `"inner_padding"` with
`"max_name_len"` and `"rounding"` (`"rfc9849"` or `"legacy"`) computed from
the ClientHelloInner as Firefox does, and `"aeads"`; the bare
`"ech_grease"` is the Chrome and Edge shape). `install_profiles` replaces them for the process with a
delivered bundle:

```json
{ "format": 1, "revision": "2026-11-10", "profiles": { "chrome": { ... }, "safari": { ... } } }
```

so following a browser release means pushing a new bundle, not shipping a new
build. A bundle is validated as a whole (unknown keys, an extension type this
build cannot encode, or a ClientHello this client could not finish a handshake
from reject it and leave the previous state), profile names this build does not
know are skipped, and fingerprints the bundle does not name go back to their
built-in data. `node-runtime` (`tls_fingerprints` in the node config and
`PUT /v1/tls-fingerprints`) and `engine-embedded` (`tls_fingerprints` in the
runtime config) are the delivery points. `hybrid_x25519` is written only when
it is `"shared"`, so only Firefox profiles carry it; builds from before the
key reject a bundle that has it, and a Firefox profile written for them
(without the key) gets a key of its own on newer builds, so a bundle with a
Firefox profile has to be made for the builds it goes to. The same holds for
the `ech_grease` parameters: they are written only when they differ from the
Chrome and Edge shape, so only Firefox profiles carry them, and builds from
before them reject a bundle that has them.

The client supports only what these protocols need: TLS 1.3 full handshakes
and resumption with a session ticket the caller offers (`connect_resuming`,
`psk_dhe_ke`, no 0-RTT) with `TLS_AES_128_GCM_SHA256`,
`TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`; `X25519`,
`X25519MLKEM768` and `P-256`; Ed25519, ECDSA P-256/P-384 and RSA-PSS
CertificateVerify; KeyUpdate. It rejects TLS 1.2, HelloRetryRequest, client
certificates and compressed certificates.

Trust is decided by the caller through `HandshakeHooks`:
`edit_client_hello` may rewrite the encoded ClientHello (REALITY uses the
session id) and `verify_server_certificates` must accept the chain. The crate
does not ship a WebPKI verifier yet, so it must not be used for ordinary HTTPS
until one is added. `TlsStream` can hand the raw transport over one direction
at a time (`start_raw_read` / `start_raw_write`) for XTLS Vision.

Hooks derive their keys from the standalone `X25519` key share
(`HelloContext::x25519_shared`, for example REALITY's auth key): every
profile has it, and REALITY-style servers read it before the `X25519` half of
an `X25519MLKEM768` share. When the server selects `X25519MLKEM768`, the
handshake uses the hybrid share's own X25519 key, so both groups work whether
or not the profile shares the key. Known fingerprint limit: a profile can
only carry key shares for `X25519`, `X25519MLKEM768` and `P-256`. Validation
is the contract test suite (including full and resumed handshakes in which
the server selects `X25519MLKEM768`) plus the `REALITY interop (Linux)` CI
job against OpenSSL, Xray-core and sing-box.

`tls_mimic::server` is the matching minimal TLS 1.3 server for REALITY-style
inbounds: the caller reads and inspects the ClientHello first
(`read_client_hello` keeps every consumed byte so the connection can be
replayed elsewhere), then `accept` finishes the handshake with an X25519 key
exchange and an Ed25519 certificate.
