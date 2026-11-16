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
//! - `wireguard` (feature `wireguard`): with a single `outbound`, an IP-level
//!   tunnel that bypasses the TCP/IP stack and seals packets straight to one
//!   peer; in `routing.outbounds`, a node like any other (`outbound-wireguard`).
//! - `mitm` (feature `mitm`): HTTPS decryption for the policy's MITM host
//!   list, offered every new TCP flow through [`tunnel::FlowInterceptor`].
//!
//! The runtime never starts a process, never touches Apple SDK objects and
//! never puts credentials or traffic into errors, status or logs.

pub mod capture;
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
#[cfg(feature = "local-proxy")]
pub mod fetch;
pub mod ffi;
#[cfg(any(feature = "local-proxy", feature = "dns-tls"))]
pub mod http1;
pub(crate) mod icmp;
#[cfg(feature = "local-proxy")]
pub mod lan_share;
#[cfg(feature = "local-proxy")]
pub mod local_proxy;
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
pub mod rule_sets;
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
/// WireGuard peer that takes IP packets directly.
enum Engine {
    Stack(Arc<Dispatcher>),
    #[cfg(feature = "wireguard")]
    WireGuard(WireGuardSettings),
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
        config.install_tls_fingerprints();
        let interceptor = build_interceptor(&config)?;
        let plugin_rules = interceptor
            .as_ref()
            .map(|interceptor| interceptor.plugin_rules())
            .unwrap_or_default();
        let routed =
            config.build_routed_with_plugin_rules(registry, dialer.clone(), &plugin_rules)?;
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
                        .with_fake_ip(config.fake_ip_pool()?);
                    dispatcher.set_mode(config.mode);
                    dispatcher.set_block_quic(config.block_quic);
                    Engine::Stack(Arc::new(dispatcher))
                }
                #[cfg(feature = "wireguard")]
                TunnelMode::WireGuard(settings) => Engine::WireGuard(settings),
            },
        };
        if let (Some(interceptor), Engine::Stack(dispatcher)) = (&interceptor, &engine) {
            interceptor.set_script_outbound(dispatcher.clone());
        }
        let mut runtime = Self::with_engine(config, engine);
        runtime.interceptor = interceptor;
        runtime.routed = routed;
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
            Engine::WireGuard(wireguard) => Tunnel::start_wireguard(wireguard.clone(), sink),
        };
        match started {
            Ok(tunnel) => {
                self.tunnel = Some(tunnel);
                self.state = RuntimeState::Running;
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
            tokio::join!(
                routed.clone().run_health_checks(),
                routed.run_rule_set_updates()
            );
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

    /// Idempotent.
    pub fn stop(&mut self) {
        #[cfg(feature = "local-proxy")]
        {
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
                Engine::WireGuard(_) => wireguard::PROTOCOL,
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
                Engine::WireGuard(_) => None,
            },
        }
    }

    /// Answers one [`control`] request, such as the connection list. A
    /// WireGuard tunnel has no flows to control and rejects every request.
    pub fn control_json(&self, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        match &self.engine {
            Engine::Stack(dispatcher) => {
                if let Some(answer) = self.lan_share_control(dispatcher, request) {
                    return answer;
                }
                control::handle_with_interceptor(dispatcher, self.interceptor.as_deref(), request)
            }
            #[cfg(feature = "wireguard")]
            Engine::WireGuard(_) => {
                let _ = request;
                Err(control::unavailable())
            }
        }
    }

    /// The commands of [`lan_share`] and [`replay_proxy`]; both listeners
    /// only run while the tunnel does.
    #[cfg(feature = "local-proxy")]
    fn lan_share_control(
        &self,
        dispatcher: &Arc<Dispatcher>,
        request: &[u8],
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        let decrypting =
            || -> Result<Option<Arc<dyn inbound_mixed::ClientInterceptor>>, RuntimeError> {
                Ok(match &self.interceptor {
                    Some(interceptor) => Some(Arc::new(local_proxy::Decrypting::new(
                        dispatcher.clone(),
                        interceptor.clone(),
                        tunnel_settings(&self.config)?,
                    ))
                        as Arc<dyn inbound_mixed::ClientInterceptor>),
                    None => None,
                })
            };
        let replay = self.replay_proxy.control(request, |decrypt| {
            if self.tunnel.is_none() {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::InvalidArgument,
                    "replay proxy needs a running tunnel",
                ));
            }
            let interceptor = if decrypt { decrypting()? } else { None };
            replay_proxy::ReplayProxy::start(dispatcher.clone(), interceptor)
        });
        if replay.is_some() {
            return replay;
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
                decrypting()?,
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
    Ok(TunnelSettings {
        mtu: config.mtu,
        tcp_window_bytes: limits.tcp_window_bytes,
        max_tcp_connections: limits.max_tcp_connections,
        max_udp_flows: limits.max_udp_flows,
        max_dns_in_flight: limits.max_dns_in_flight,
        idle_timeout: Duration::from_secs(limits.idle_timeout_secs),
        connect_timeout: Duration::from_secs(limits.connect_timeout_secs),
        dns: Arc::new(dns),
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
