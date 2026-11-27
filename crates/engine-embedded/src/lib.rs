//! Embedded engine for the iOS Network Extension.
//!
//! Layers, from the C ABI inward:
//!
//! - [`ffi`]: the `networkcore_ios_*` C ABI that the Swift packet tunnel calls.
//! - [`EmbeddedRuntime`]: validated config, outbound selection and lifecycle.
//! - [`tunnel`]: userspace TCP/IP (smoltcp) that turns packets into flows,
//!   with [`sniff`] reading the host name of each TCP flow.
//! - [`connections`]: the dispatcher every flow goes through, which routes
//!   it and keeps the connection list and traffic counters that [`control`]
//!   requests read.
//! - [`pro`]: the switch for the closed Pro debugging modules of official
//!   builds; a community build reports no Pro features.
//! - [`capture`]: opt-in capture of connection bytes and decrypted HTTP
//!   messages under a memory budget, exported as pcapng or HAR.
//! - Outbounds implementing [`engine_outbound::TcpOutbound`], looked up by
//!   config `type` in the registry from [`protocols`]: Shadowsocks-2022
//!   (`outbound-shadowsocks`), VLESS + REALITY (`outbound-vless`) and direct
//!   ([`direct`]). Each protocol is a cargo feature, so it can be added or
//!   left out without touching the tunnel. [`routing`] wraps several of them
//!   behind the shared `config-core` rules and policy groups.
//! - `local_proxy` (feature `local-proxy`): the desktop mode, the same
//!   outbounds behind a SOCKS5/HTTP listener from `inbound-mixed`, and
//!   `delay`, URL delay tests of a node's outbound.
//! - `lan_share` (feature `local-proxy`): the running engine opened to
//!   phones on the local network that set this computer as their proxy,
//!   with a setup page for the root certificate.
//! - `replay_proxy` (feature `local-proxy`): a `127.0.0.1` listener with
//!   one-time credentials for the client's own requests (replays).
//! - `system_proxy` (feature `local-proxy`): the packet tunnel's HTTP/SOCKS5
//!   listener on `127.0.0.1` that iOS and macOS register as the system
//!   proxy, next to the tunnel or (macOS) instead of it.
//! - `wireguard` (feature `wireguard`): with a single `outbound`, an IP-level
//!   tunnel that bypasses the TCP/IP stack and seals packets straight to one
//!   peer; in `routing.outbounds`, a node like any other (`outbound-wireguard`).
//!   Both move to a new UDP socket on `reset_network`.
//! - `mitm` (feature `mitm`): HTTPS decryption for the policy's MITM host
//!   list, offered every new TCP flow through [`tunnel::FlowInterceptor`].
//!
//! The runtime never starts a process, never touches Apple SDK objects and
//! never puts credentials or traffic into errors, status or logs.

pub mod capture;
pub mod capture_viewer;
#[cfg(feature = "local-proxy")]
pub mod checkup;
pub mod config;
pub mod connections;
pub mod control;
#[cfg(feature = "local-proxy")]
pub mod delay;
pub mod direct;
pub mod dns;
pub mod dns_cache;
pub mod dns_client;
pub mod dns_policy;
#[cfg(feature = "dns-quic")]
pub mod dns_quic;
pub mod dns_resolver;
pub mod fake_ip;
pub(crate) mod fd_budget;
#[cfg(feature = "local-proxy")]
pub mod fetch;
pub mod ffi;
pub mod first_payload;
#[cfg(any(feature = "local-proxy", feature = "dns-tls"))]
pub mod http1;
pub(crate) mod icmp;
pub mod interface;
pub mod lan_guard;
#[cfg(feature = "local-proxy")]
pub mod lan_share;
#[cfg(feature = "local-proxy")]
pub mod local_proxy;
#[cfg(feature = "mesh")]
pub(crate) mod mesh;
pub mod metrics;
#[cfg(feature = "mitm")]
pub mod mitm;
pub mod nodes;
pub mod pro;
#[cfg(feature = "local-proxy")]
pub mod process;
pub mod profile;
pub mod protocols;
pub mod reject;
#[cfg(feature = "local-proxy")]
pub mod replay_proxy;
pub mod routing;
pub mod rule_scripts;
pub mod rule_set_cache;
pub mod rule_sets;
#[cfg(feature = "local-proxy")]
pub mod system_proxy;
pub use engine_outbound::protect;
pub use engine_outbound::sniff;
pub mod tunnel;
#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "shadowsocks")]
pub use outbound_shadowsocks as shadowsocks;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{Dialer, TcpDialer, TcpOutbound};
use serde::Serialize;

use crate::config::{RuntimeConfig, TunnelMode};
use crate::connections::Dispatcher;
use crate::dns_policy::DnsPolicy;
use crate::routing::RoutedOutbound;
use crate::tunnel::{FlowInterceptor, PacketWriter, Tunnel, TunnelSettings, TunnelStatsSnapshot};
#[cfg(feature = "wireguard")]
use crate::wireguard::WireGuardSettings;

/// Stable error categories. They map one-to-one onto the FFI error codes and
/// the `platform.ios.embedded_runtime.*` diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeErrorCode {
    InvalidArgument,
    SchemaMismatch,
    ConfigRejected,
    ResourceExhausted,
    PanicCaught,
    InternalError,
}

impl RuntimeErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeErrorCode::InvalidArgument => "invalid_argument",
            RuntimeErrorCode::SchemaMismatch => "schema_mismatch",
            RuntimeErrorCode::ConfigRejected => "config_rejected",
            RuntimeErrorCode::ResourceExhausted => "resource_exhausted",
            RuntimeErrorCode::PanicCaught => "panic_caught",
            RuntimeErrorCode::InternalError => "internal_error",
        }
    }
}

/// An error with a fixed, credential-free message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub message: &'static str,
}

impl RuntimeError {
    pub fn new(code: RuntimeErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Initialized,
    Running,
    Stopped,
}

/// Sanitized status: identifiers, state and counters only.
#[derive(Clone, Debug, Serialize)]
pub struct RuntimeStatus {
    pub abi_version: u32,
    pub schema_version: u32,
    pub profile_id: String,
    pub outbound: &'static str,
    pub state: RuntimeState,
    pub last_error: Option<&'static str>,
    pub stats: TunnelStatsSnapshot,
    /// Fake-IP table counters, when `dns.fake_ip` is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip: Option<fake_ip::FakeIpStats>,
}

/// What carries the traffic: a TCP outbound behind the userspace stack, or a
/// WireGuard peer that takes IP packets directly, with the handle that moves
/// its running tunnel to a new UDP socket.
enum Engine {
    Stack(Arc<Dispatcher>),
    #[cfg(feature = "wireguard")]
    WireGuard(WireGuardSettings, Arc<wireguard::PathControl>),
}

pub struct EmbeddedRuntime {
    config: RuntimeConfig,
    engine: Engine,
    /// The rule-based outbound of a `routing` config, kept to run its url-test
    /// and fallback health checks while the tunnel runs.
    routed: Option<Arc<RoutedOutbound>>,
    interceptor: Option<Arc<dyn FlowInterceptor>>,
    tunnel: Option<Tunnel>,
    state: RuntimeState,
    last_error: Option<RuntimeErrorCode>,
    last_stats: TunnelStatsSnapshot,
    #[cfg(feature = "local-proxy")]
    lan_share: lan_share::LanShareSlot,
    #[cfg(feature = "local-proxy")]
    replay_proxy: replay_proxy::ReplayProxySlot,
    #[cfg(feature = "local-proxy")]
    system_proxy: system_proxy::SystemProxySlot,
    /// The mesh outbounds' link to the process's mesh engine.
    #[cfg(feature = "mesh")]
    mesh: mesh::MeshBinding,
}

impl EmbeddedRuntime {
    pub fn from_json(bytes: &[u8]) -> Result<Self, RuntimeError> {
        Self::with_dialer(bytes, Arc::new(TcpDialer))
    }

    pub fn with_dialer(bytes: &[u8], dialer: Arc<dyn Dialer>) -> Result<Self, RuntimeError> {
        Self::with_registry(bytes, &protocols::default_registry(), dialer)
    }

    /// Builds outbounds from `registry` instead of the feature-selected one,
    /// e.g. to add a protocol crate that lives outside this repository.
    pub fn with_registry(
        bytes: &[u8],
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, RuntimeError> {
        let config = RuntimeConfig::from_json(bytes)?;
        // Mesh outbounds of this profile find their network in the mesh
        // engine, which the runtime commits them to once its tunnel runs.
        #[cfg(feature = "mesh")]
        let mesh = mesh::MeshBinding::default();
        #[cfg(feature = "mesh")]
        let bound = mesh.bind(registry);
        #[cfg(feature = "mesh")]
        let registry = &bound;
        config.install_tls_fingerprints();
        let interceptor = build_interceptor(&config)?;
        let plugin_rules = interceptor
            .as_ref()
            .map(|interceptor| interceptor.plugin_rules())
            .unwrap_or_default();
        let routed =
            config.build_routed_with_plugin_rules(registry, dialer.clone(), &plugin_rules)?;
        #[cfg(feature = "mesh")]
        if let (Some(routed), Some(routing)) = (&routed, &config.routing) {
            mesh.route(routed, &routing.outbounds);
        }
        let engine = match &routed {
            Some(routed) => Engine::Stack(Arc::new(config.build_dispatcher(
                Some(routed.clone()),
                registry,
                dialer,
            )?)),
            None => match config.build_mode(registry, dialer.clone())? {
                TunnelMode::Stack(outbound) => {
                    let dispatcher = Dispatcher::single(outbound)
                        .with_direct(Arc::new(direct::DirectOutbound::new(dialer)))
                        .with_redirects(config.redirect_table()?)
                        .with_fake_ip(config.runtime_fake_ip_pool()?);
                    dispatcher.set_mode(config.mode);
                    dispatcher.set_block_quic(config.block_quic);
                    Engine::Stack(Arc::new(dispatcher))
                }
                #[cfg(feature = "wireguard")]
                TunnelMode::WireGuard(settings) => Engine::WireGuard(settings, Arc::default()),
            },
        };
        if let (Some(interceptor), Engine::Stack(dispatcher)) = (&interceptor, &engine) {
            interceptor.set_script_outbound(dispatcher.clone());
        }
        let mut runtime = Self::with_engine(config, engine);
        runtime.interceptor = interceptor;
        runtime.routed = routed;
        #[cfg(feature = "mesh")]
        {
            runtime.mesh = mesh;
        }
        Ok(runtime)
    }

    /// Uses a caller-provided outbound, for tests and future protocol crates.
    pub fn with_outbound(config: RuntimeConfig, outbound: Arc<dyn TcpOutbound>) -> Self {
        let dispatcher = Dispatcher::single(outbound);
        dispatcher.set_block_quic(config.block_quic);
        Self::with_engine(config, Engine::Stack(Arc::new(dispatcher)))
    }

    fn with_engine(config: RuntimeConfig, engine: Engine) -> Self {
        Self {
            config,
            engine,
            routed: None,
            interceptor: None,
            tunnel: None,
            state: RuntimeState::Initialized,
            last_error: None,
            last_stats: TunnelStatsSnapshot::default(),
            #[cfg(feature = "local-proxy")]
            lan_share: lan_share::LanShareSlot::default(),
            #[cfg(feature = "local-proxy")]
            replay_proxy: replay_proxy::ReplayProxySlot::default(),
            #[cfg(feature = "local-proxy")]
            system_proxy: system_proxy::SystemProxySlot::default(),
            #[cfg(feature = "mesh")]
            mesh: mesh::MeshBinding::default(),
        }
    }

    pub fn start(&mut self, sink: impl PacketWriter) -> Result<(), RuntimeError> {
        if self.tunnel.is_some() {
            return Err(self.fail(RuntimeError::new(
                RuntimeErrorCode::InvalidArgument,
                "tunnel is already running",
            )));
        }
        let settings = match tunnel_settings(&self.config) {
            Ok(settings) => settings,
            Err(err) => return Err(self.fail(err)),
        };
        let started = match &self.engine {
            Engine::Stack(dispatcher) => Tunnel::start_with_dispatcher(
                settings,
                dispatcher.clone(),
                self.interceptor.clone(),
                self.health_checks(),
                sink,
            ),
            #[cfg(feature = "wireguard")]
            Engine::WireGuard(wireguard, paths) => {
                Tunnel::start_wireguard(wireguard.clone(), paths.clone(), sink)
            }
        };
        match started {
            Ok(tunnel) => {
                self.tunnel = Some(tunnel);
                self.state = RuntimeState::Running;
                // The profile is adopted now: its mesh networks are
                // committed only after the tunnel runs.
                #[cfg(feature = "mesh")]
                self.mesh.commit();
                Ok(())
            }
            Err(_) => Err(self.fail(RuntimeError::new(
                RuntimeErrorCode::ResourceExhausted,
                "tunnel could not start",
            ))),
        }
    }

    /// The url-test and fallback health checks and the remote rule set
    /// updates of a routed config. They go through the outbounds like the
    /// delay test, which the `local-proxy` feature builds.
    #[cfg(feature = "local-proxy")]
    fn health_checks(&self) -> Option<engine_outbound::BoxFuture<'static, ()>> {
        let routed = self.routed.clone()?;
        Some(Box::pin(async move {
            // Each on its own task, so a panic in one (in a rule set
            // download, say) does not stop the other.
            let checks = tokio::spawn(routed.clone().run_health_checks());
            let rule_sets = tokio::spawn(routed.run_rule_set_updates());
            let _ = tokio::join!(checks, rule_sets);
        }))
    }

    #[cfg(not(feature = "local-proxy"))]
    fn health_checks(&self) -> Option<engine_outbound::BoxFuture<'static, ()>> {
        None
    }

    /// Returns `false` when the packet was dropped.
    pub fn input_packet(&self, packet: &[u8]) -> bool {
        match &self.tunnel {
            Some(tunnel) => tunnel.input_packet(packet),
            None => false,
        }
    }

    /// Idempotent. The mesh engine keeps running for the grace period, for
    /// the next profile to take over; `mesh_engine_stop` before the stop
    /// ends it at once.
    pub fn stop(&mut self) {
        #[cfg(feature = "mesh")]
        self.mesh.release();
        #[cfg(feature = "local-proxy")]
        {
            self.system_proxy.stop();
            self.lan_share.stop();
            self.replay_proxy.stop();
        }
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
            self.last_stats = tunnel.stats();
            self.state = RuntimeState::Stopped;
        }
    }

    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            abi_version: ffi::NETWORKCORE_IOS_ABI_VERSION,
            schema_version: config::CONFIG_SCHEMA_VERSION,
            profile_id: self.config.profile_id.clone(),
            outbound: match &self.engine {
                Engine::Stack(dispatcher) => dispatcher.protocol(),
                #[cfg(feature = "wireguard")]
                Engine::WireGuard(..) => wireguard::PROTOCOL,
            },
            state: self.state,
            last_error: self.last_error.map(RuntimeErrorCode::as_str),
            stats: match &self.tunnel {
                Some(tunnel) => tunnel.stats(),
                None => self.last_stats.clone(),
            },
            fake_ip: match &self.engine {
                Engine::Stack(dispatcher) => dispatcher.fake_ip().map(|pool| pool.stats()),
                #[cfg(feature = "wireguard")]
                Engine::WireGuard(..) => None,
            },
        }
    }

    /// Answers one [`control`] request, such as the connection list. A
    /// WireGuard tunnel has no flows to control: it answers `reset_network`
    /// (moving to a new UDP socket) and `set_network`, and rejects every
    /// other request.
    pub fn control_json(&self, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let mesh = cfg!(feature = "mesh") && self.config.allow_mesh;
        if let Some(answer) = feature_control(request, mesh) {
            return answer;
        }
        #[cfg(feature = "mesh")]
        if mesh {
            if let Some(answer) = self.mesh.control(request) {
                return answer;
            }
        }
        match &self.engine {
            Engine::Stack(dispatcher) => {
                if let Some(answer) = self.lan_share_control(dispatcher, request) {
                    return answer;
                }
                control::handle_with_interceptor(dispatcher, self.interceptor.as_deref(), request)
            }
            #[cfg(feature = "wireguard")]
            Engine::WireGuard(_, paths) => control::handle_wireguard(paths, request),
        }
    }

    /// The commands of [`lan_share`], [`replay_proxy`] and [`system_proxy`];
    /// the listeners stop with the runtime.
    #[cfg(feature = "local-proxy")]
    fn lan_share_control(
        &self,
        dispatcher: &Arc<Dispatcher>,
        request: &[u8],
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        // Each listener names its decrypted connections as its connector
        // names the others, for `PROCESS-NAME` rules and the list.
        let decrypting = |process: local_proxy::ClientProcess| -> Result<
            Option<Arc<local_proxy::Decrypting>>,
            RuntimeError,
        > {
            Ok(match &self.interceptor {
                Some(interceptor) => Some(Arc::new(local_proxy::Decrypting::new(
                    dispatcher.clone(),
                    interceptor.clone(),
                    tunnel_settings(&self.config)?,
                    process,
                ))),
                None => None,
            })
        };
        let as_interceptor = |decrypting: Option<Arc<local_proxy::Decrypting>>| {
            decrypting.map(|decrypting| decrypting as Arc<dyn inbound_mixed::ClientInterceptor>)
        };
        let replay = self.replay_proxy.control(request, |decrypt| {
            if self.tunnel.is_none() {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::InvalidArgument,
                    "replay proxy needs a running tunnel",
                ));
            }
            let interceptor = if decrypt {
                as_interceptor(decrypting(local_proxy::ClientProcess::Named(
                    replay_proxy::PROCESS_NAME,
                ))?)
            } else {
                None
            };
            replay_proxy::ReplayProxy::start(dispatcher.clone(), interceptor)
        });
        if replay.is_some() {
            return replay;
        }
        // Unlike the other listeners it may start before the tunnel: the
        // provider registers its port with the interface settings, which it
        // applies before the tunnel reads packets. Stopping or dropping the
        // runtime stops it either way.
        let system = self.system_proxy.control(request, |port| {
            system_proxy::SystemProxy::start(
                dispatcher.clone(),
                as_interceptor(decrypting(local_proxy::ClientProcess::Local)?),
                system_proxy::SystemProxyOptions {
                    port,
                    max_connections: fd_budget::connection_limits(&self.config.limits).proxy_tcp,
                },
            )
        });
        if system.is_some() {
            return system;
        }
        self.lan_share.control(request, |options| {
            if self.tunnel.is_none() {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::InvalidArgument,
                    "lan share needs a running tunnel",
                ));
            }
            lan_share::LanShare::start(
                dispatcher.clone(),
                // The share marks its devices' decrypted flows for
                // `crate::lan_guard` (`Decrypting::for_clients`).
                decrypting(local_proxy::ClientProcess::LanDevice {
                    block_private_networks: options.block_private_networks,
                })?,
                self.config.mitm_ca_certificate_der(),
                options,
            )
        })
    }

    #[cfg(not(feature = "local-proxy"))]
    fn lan_share_control(
        &self,
        _dispatcher: &Arc<Dispatcher>,
        _request: &[u8],
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        None
    }

    fn fail(&mut self, err: RuntimeError) -> RuntimeError {
        self.last_error = Some(err.code);
        err
    }
}

/// Stack settings of `config`: its MTU, limits and DNS policy.
pub(crate) fn tunnel_settings(config: &RuntimeConfig) -> Result<TunnelSettings, RuntimeError> {
    let dns = DnsPolicy::from_config(&config.dns)
        .map_err(|message| RuntimeError::new(RuntimeErrorCode::ConfigRejected, message))?;
    let limits = &config.limits;
    // Lowered to the descriptor budget, so idle connections make room
    // before the process runs out of file descriptors.
    let caps = fd_budget::connection_limits(limits);
    let (max_tcp_connections, max_udp_flows) = (caps.tunnel_tcp, caps.udp);
    Ok(TunnelSettings {
        mtu: config.mtu,
        tcp_window_bytes: limits.tcp_window_bytes,
        max_tcp_connections,
        max_udp_flows,
        tcp_evict_idle: tunnel::DEFAULT_TCP_EVICT_IDLE,
        udp_evict_idle: tunnel::DEFAULT_UDP_EVICT_IDLE,
        max_dns_in_flight: limits.max_dns_in_flight,
        idle_timeout: Duration::from_secs(limits.idle_timeout_secs),
        connect_timeout: Duration::from_secs(limits.connect_timeout_secs),
        dns: Arc::new(dns),
        worker_threads: match limits.worker_threads {
            0 => tunnel::default_worker_threads(),
            n => n,
        },
    })
}

/// The HTTPS decryption interceptor for the config's `mitm` section.
pub(crate) fn build_interceptor(
    config: &RuntimeConfig,
) -> Result<Option<Arc<dyn FlowInterceptor>>, RuntimeError> {
    let Some(mitm) = config.mitm.as_ref() else {
        return Ok(None);
    };
    #[cfg(feature = "mitm")]
    {
        let engine = mitm::MitmEngine::new(mitm)
            .map_err(|message| RuntimeError::new(RuntimeErrorCode::ConfigRejected, message))?;
        Ok(Some(Arc::new(engine)))
    }
    #[cfg(not(feature = "mitm"))]
    {
        let _ = mitm;
        Err(RuntimeError::new(
            RuntimeErrorCode::ConfigRejected,
            "mitm is not supported by this build",
        ))
    }
}

impl Drop for EmbeddedRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `{"cmd": "capabilities"}`: what this runtime runs,
/// `{"capabilities": {"mesh": bool}}` (`mesh-status.md`). `mesh` says
/// whether this runtime answers `mesh_*` commands: the VPN runtime does when
/// the engine is built with the `mesh` feature and its config sets
/// `allow_mesh`, the desktop local proxy never does. When it does not, every `mesh_*` command answers
/// `unsupported` here. `None` for any other request.
///
/// `capabilities` is answered up to [`control::MAX_REQUEST_LEN`] bytes, like
/// the other short commands; a `mesh_*` command up to
/// [`control::MAX_RELOAD_REQUEST_LEN`], like the mesh commands it stands for.
/// Longer requests go on to the other handlers, which refuse their length.
/// A command name written with JSON escapes (`"capabilit\u0069es"`) is not
/// guaranteed to be recognised: the byte test only finds it when the plain
/// name also appears elsewhere in the request.
pub(crate) fn feature_control(request: &[u8], mesh: bool) -> Option<Result<Vec<u8>, RuntimeError>> {
    if !control::names(request, b"capabilities") && (mesh || !control::names(request, b"mesh_")) {
        return None;
    }
    let name = control::command_name(request)?;
    let answer = if name == "capabilities" {
        if request.len() > control::MAX_REQUEST_LEN {
            return None;
        }
        serde_json::json!({"capabilities": {"mesh": mesh}})
    } else if !mesh && name.starts_with("mesh_") {
        serde_json::json!({
            "ok": false,
            "error": {"code": "unsupported", "detail": "this runtime does not run mesh networks"},
        })
    } else {
        return None;
    };
    Some(serde_json::to_vec(&answer).map_err(|_| {
        RuntimeError::new(
            RuntimeErrorCode::InternalError,
            "capabilities answer could not be encoded",
        )
    }))
}

#[cfg(test)]
mod feature_control_tests {
    use super::feature_control;
    use serde_json::{json, Value};

    fn ask(request: &str, mesh: bool) -> Option<Value> {
        feature_control(request.as_bytes(), mesh)
            .map(|answer| serde_json::from_slice(&answer.unwrap()).unwrap())
    }

    #[test]
    fn the_capabilities_say_whether_mesh_networks_are_answered() {
        for mesh in [true, false] {
            assert_eq!(
                ask(r#"{"cmd":"capabilities"}"#, mesh),
                Some(json!({"capabilities": {"mesh": mesh}}))
            );
            assert_eq!(
                ask(r#"{"cmd":"traffic","note":"capabilities"}"#, mesh),
                None
            );
            assert_eq!(ask(r#"["capabilities"]"#, mesh), None);
            assert_eq!(ask(r#"{"cmd":"traffic"}"#, mesh), None);
        }
        // The mesh binding answers it.
        assert_eq!(ask(r#"{"cmd":"mesh_status"}"#, true), None);
        let refused = ask(r#"{"cmd":"mesh_status"}"#, false).unwrap();
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["error"]["code"], "unsupported");
    }

    #[test]
    fn a_mesh_word_inside_another_command_is_not_a_mesh_command() {
        assert_eq!(
            ask(r#"{"cmd":"traffic","note":"mesh_status"}"#, false),
            None
        );
        assert_eq!(ask(r#"{"note":"mesh_status"}"#, false), None);
    }

    #[test]
    fn nested_values_and_oversized_requests_are_left_to_the_other_handlers() {
        // Every field but `cmd` is skipped unread, however deep it nests.
        let deep = format!(
            r#"{{"cmd":"capabilities","x":{}1{}}}"#,
            "[".repeat(1000),
            "]".repeat(1000)
        );
        assert_eq!(
            ask(&deep, false),
            Some(json!({"capabilities": {"mesh": false}}))
        );
        let shallow = r#"{"x":[[{"cmd":"mesh_status"}]],"cmd":"capabilities"}"#;
        assert_eq!(
            ask(shallow, false),
            Some(json!({"capabilities": {"mesh": false}}))
        );
        // `capabilities` is a short command.
        let padded = |cmd: &str, length: usize| {
            let head = format!(r#"{{"cmd":"{cmd}","pad":""#);
            format!("{head}{}\"}}", "x".repeat(length - head.len() - 2))
        };
        let short = padded("capabilities", crate::control::MAX_REQUEST_LEN);
        assert_eq!(short.len(), crate::control::MAX_REQUEST_LEN);
        assert!(ask(&short, false).is_some());
        let long = padded("capabilities", crate::control::MAX_REQUEST_LEN + 1);
        assert_eq!(ask(&long, false), None);
        // A `mesh_*` command is refused up to the mesh commands' limit.
        let mesh = padded("mesh_status", crate::control::MAX_RELOAD_REQUEST_LEN);
        assert_eq!(ask(&mesh, false).unwrap()["error"]["code"], "unsupported");
        let mesh = padded("mesh_status", crate::control::MAX_RELOAD_REQUEST_LEN + 1);
        assert_eq!(ask(&mesh, false), None);
        // An escaped command name is not guaranteed to be recognised: alone,
        // it misses the byte test; next to the plain name, it is read.
        assert_eq!(ask(r#"{"cmd":"capabilit\u0069es"}"#, false), None);
        assert!(ask(r#"{"cmd":"capabilit\u0069es","n":"capabilities"}"#, false).is_some());
    }
}
