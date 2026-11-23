# platform-windows

`platform-windows` provides the native system-integration boundary shared by the
NetworkCore GUI, service, installer, and CLI.

Current status:

- `WINDOWS_CLI_ARTIFACT_GATE=windows-managed-client-active`
- `windows-cli-artifact-source-identity=apps/windows-cli`
- `windows-cli-artifact-package-windows=defined`
- Windows service, signed INF driver package lifecycle, WiX MSI installer,
  system proxy mutation, system trust store mutation, and managed daemon
  lifecycle are active.
- The managed schema has an optional `embedded` block: an engine-embedded
  configuration envelope path and a loopback listener. The service runs that
  engine in-process, polls it, and routes a failure through failed-state
  cleanup and proxy rollback. No third-party proxy core is started.
- `root_certificate_path` remains a generic trust-store installation only. The
  separate `native_mitm` block powers the explicit GUI-controlled loopback HTTP
  listener, service-owned CA lifecycle, controlled TLS termination, and the
  embedded engine as its local SOCKS upstream. It handles one bounded HTTP/1.1 exchange only; it
  does not provide HTTP/2, QUIC, streaming, or transparent capture.
- JavaScript script dispatch remains blocked.

`managed` owns the schema-versioned ProgramData configuration and state records.
`system_integration` calls SCM, WinINet/WinHTTP, CryptoAPI, and NewDev directly
(the system proxy is applied per WinINet connection; the machine-wide WinHTTP
proxy is only read, see `docs/architecture/windows-platform-integration.md`)
and exposes apply, status, rollback, and uninstall operations.

The installed default configuration is intentionally inert: all optional
operations are `null` until an operator supplies absolute paths or proxy
settings. The GUI and service append diagnostics under
`%ProgramData%\\AnixOps\\NetworkCore\\logs`; errors are always recorded, while
verbose GUI status logging can be toggled from the desktop client or enabled
with `networkcore-windows-gui.exe --debug` (the GUI and service live in
[AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)).

## TUN mode

`tun` creates a Wintun adapter for system-wide capture. The client ships
`wintun.dll` next to its executable and passes that absolute path to
`WindowsTun::open`; the DLL is never loaded from the search path. The adapter
gets `172.19.0.1/30` (DNS `172.19.0.2`, answered by the tunnel) and
`fdfe:dcba:9876::1/126`, and the capture routes `0.0.0.0/1`, `128.0.0.0/1`,
`::/1` and `8000::/1`. Closing the adapter removes its address and routes, so
the physical default route is never touched.

The physical interface of each family is recorded before the routes go in.
The host installs an `engine_outbound::protect` socket protector that calls
`PhysicalInterfaceHandle::bind_socket` on `WindowsTun::physical_interface_handle`
(`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) so the engine's own sockets to proxy
servers, DNS upstreams and direct destinations do not loop back into the
adapter.

The physical interface follows network changes while the adapter is open.
A watcher registered with `NotifyRouteChange2` and `NotifyIpInterfaceChange`
waits until the burst of notifications settles (0.5 s quiet, at most 3 s),
reads the routing table (`GetIpForwardTable2`) and picks, per family, the
connected interface with a default route (`0.0.0.0/0`, `::/0`) and the lowest
route + interface metric, never the TUN adapter itself (its capture routes
make `GetBestInterfaceEx` answer with the adapter). The shared handle is
updated in place, so every socket made afterwards uses the new interface; a
family that has lost its default route fails with `NetworkUnreachable`
instead of looping into the adapter, and gains one again when IPv6 arrives
later. `WindowsTun::on_physical_interface_change` runs a host callback after
each change: the host reports it with `engine_outbound::protect::path_changed`
(a WireGuard node moves its UDP socket) and sends the engine `reset_network`
so connections still pinned to the old interface close and reconnect.
`WindowsTun::refresh_physical_interface` does the same pick on demand, for a
host that noticed a change (or a wake from sleep) itself.
