//! Local proxy mode for desktop: the same config envelope and outbounds as the
//! packet tunnel, served as a SOCKS5/HTTP mixed inbound on a local port.
//!
//! Applications (or the system proxy setting) send their connections to the
//! listener, so routing rules see the requested domain instead of an IP. The
//! proxy owns one current-thread tokio runtime on a dedicated thread, like
//! [`crate::tunnel::Tunnel`]. With `PROCESS-NAME` rules each connection's
//! local process is looked up ([`crate::process`]) before it is routed.
//!
//! A config with a `mitm` section gets the same HTTPS decryption as the
//! packet tunnel: each connection's first bytes are offered to the
//! [`FlowInterceptor`], and what it does not claim is relayed untouched.
//!
//! The `start_lan_share` control request opens the same engine to phones on
//! the local network; see [`crate::lan_share`]. `start_replay_proxy` opens
//! a `127.0.0.1` listener for the client's own requests; see
//! [`crate::replay_proxy`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound};
use inbound_mixed::{ClientAddrs, ClientConnector, ClientInterceptor, MixedSettings, MixedStats};
use tokio::sync::oneshot;

use crate::config::RuntimeConfig;
use crate::connections::{Dispatcher, FlowOrigin};
use crate::lan_share::{LanShare, LanShareSlot};
use crate::replay_proxy::{ReplayProxy, ReplayProxySlot};
use crate::routing::FlowSource;
use crate::tunnel::{
    FlowInterceptor, InterceptedFlow, TunnelSettings, TunnelStats, TunnelStatsSnapshot,
};
use crate::{control, protocols, sniff, RuntimeError, RuntimeErrorCode};

pub struct LocalProxy {
    profile_id: String,
    protocol: &'static str,
    dispatcher: Arc<Dispatcher>,
    decrypting: Option<Arc<Decrypting>>,
    local_addr: SocketAddr,
    stats: Arc<MixedStats>,
    /// Root certificate of the `mitm` section (DER), for the share's setup page.
    ca_certificate: Option<Vec<u8>>,
    lan_share: LanShareSlot,
    replay_proxy: ReplayProxySlot,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LocalProxy {
    /// Builds the outbound from `config` and starts listening on `listen`.
    /// Port 0 picks a free port; see [`LocalProxy::local_addr`].
    pub fn start(
        config: &[u8],
        listen: SocketAddr,
        settings: MixedSettings,
    ) -> Result<Self, RuntimeError> {
        Self::start_with(
            config,
            listen,
            settings,
            &protocols::default_registry(),
            Arc::new(TcpDialer),
        )
    }

    pub fn start_with(
        config: &[u8],
        listen: SocketAddr,
        settings: MixedSettings,
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, RuntimeError> {
        let config = RuntimeConfig::from_json(config)?;
        let ca_certificate = config.mitm_ca_certificate_der();
        // A routing config keeps its routed outbound to run group health checks.
        let interceptor = crate::build_interceptor(&config)?;
        let plugin_rules = interceptor
            .as_ref()
            .map(|interceptor| interceptor.plugin_rules())
            .unwrap_or_default();
        let routed =
            config.build_routed_with_plugin_rules(registry, dialer.clone(), &plugin_rules)?;
        let dispatcher = Arc::new(config.build_dispatcher(routed.clone(), registry, dialer)?);
        let protocol = dispatcher.protocol();
        let decrypting = match interceptor {
            Some(interceptor) => {
                interceptor.set_script_outbound(dispatcher.clone());
                Some(Arc::new(Decrypting::new(
                    dispatcher.clone(),
                    interceptor,
                    crate::tunnel_settings(&config)?,
                )))
            }
            None => None,
        };
        let background = decrypting
            .as_ref()
            .and_then(|decrypting| decrypting.interceptor.clone().background());
        let client_interceptor = decrypting
            .clone()
            .map(|decrypting| decrypting as Arc<dyn ClientInterceptor>);
        let connector = Arc::new(ProcessRouting(dispatcher.clone())) as Arc<dyn ClientConnector>;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| resource("local proxy runtime could not start"))?;
        let listener = {
            let _guard = runtime.enter();
            let std_listener = std::net::TcpListener::bind(listen)
                .map_err(|_| resource("local proxy address could not be bound"))?;
            std_listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(std_listener))
                .map_err(|_| resource("local proxy listener could not start"))?
        };
        let local_addr = listener
            .local_addr()
            .map_err(|_| resource("local proxy listener could not start"))?;
        let stats = Arc::new(MixedStats::default());
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread_stats = stats.clone();
        let thread = thread::Builder::new()
            .name("networkcore-local-proxy".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let health_checks = async move {
                        match routed {
                            Some(routed) => {
                                tokio::join!(
                                    routed.clone().run_health_checks(),
                                    routed.run_rule_set_updates()
                                );
                            }
                            None => std::future::pending().await,
                        }
                    };
                    let background = async move {
                        match background {
                            Some(background) => background.await,
                            None => std::future::pending().await,
                        }
                    };
                    let serve = inbound_mixed::serve_intercepted(
                        listener,
                        connector,
                        client_interceptor,
                        settings,
                        thread_stats,
                    );
                    tokio::select! {
                        _ = serve => {}
                        _ = async { tokio::join!(health_checks, background) } => {}
                        _ = shutdown_rx => {}
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .map_err(|_| resource("local proxy thread could not start"))?;
        Ok(Self {
            profile_id: config.profile_id,
            protocol,
            dispatcher,
            decrypting,
            local_addr,
            stats,
            ca_certificate,
            lan_share: LanShareSlot::default(),
            replay_proxy: ReplayProxySlot::default(),
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Protocol tag of the outbound, `"routed"` for a routing config.
    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    pub fn stats(&self) -> &MixedStats {
        &self.stats
    }

    /// Whether the config's `mitm` section is in effect on this listener.
    pub fn decrypts_https(&self) -> bool {
        self.decrypting.is_some()
    }

    /// Counters of the HTTPS decryption (`mitm_flows`, `mitm_failed`); the
    /// packet counters stay zero in this mode.
    pub fn mitm_stats(&self) -> TunnelStatsSnapshot {
        self.decrypting
            .as_ref()
            .map(|decrypting| decrypting.stats.snapshot())
            .unwrap_or_default()
    }

    /// Answers one [`control`] request, such as the connection list.
    pub fn control_json(&self, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let replay = self.replay_proxy.control(request, |decrypt| {
            let interceptor = if decrypt {
                self.decrypting
                    .clone()
                    .map(|decrypting| decrypting as Arc<dyn ClientInterceptor>)
            } else {
                None
            };
            ReplayProxy::start(self.dispatcher.clone(), interceptor)
        });
        if let Some(answer) = replay {
            return answer;
        }
        let shared = self.lan_share.control(request, |options| {
            LanShare::start(
                self.dispatcher.clone(),
                self.decrypting
                    .clone()
                    .map(|decrypting| decrypting as Arc<dyn ClientInterceptor>),
                self.ca_certificate.clone(),
                options,
            )
        });
        if let Some(answer) = shared {
            return answer;
        }
        let interceptor = self
            .decrypting
            .as_ref()
            .map(|decrypting| decrypting.interceptor.as_ref());
        control::handle_with_interceptor(&self.dispatcher, interceptor, request)
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    /// Stops listening and drops every connection. Idempotent.
    pub fn stop(&mut self) {
        self.lan_share.stop();
        self.replay_proxy.stop();
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Blocks until the proxy stops on its own (the listener failed).
    pub fn wait(&mut self) -> io::Result<()> {
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| io::Error::other("local proxy thread panicked")),
            None => Ok(()),
        }
    }
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Routes each client's connections, naming its local process when a
/// `PROCESS-NAME` rule needs it.
struct ProcessRouting(Arc<Dispatcher>);

impl ClientConnector for ProcessRouting {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let process = if self.0.wants_process() {
                tokio::task::spawn_blocking(move || {
                    crate::process::process_name(client.peer, client.local)
                })
                .await
                .ok()
                .flatten()
            } else {
                None
            };
            let origin = FlowOrigin {
                process: process.as_deref(),
                source: client_source(client),
            };
            self.0.connect_origin_flow(target, None, origin, None).await
        })
    }
}

/// The config's `mitm` section on the local listener: claimed connections go
/// to the same [`FlowInterceptor`] the packet tunnel uses.
pub(crate) struct Decrypting {
    dispatcher: Arc<Dispatcher>,
    interceptor: Arc<dyn FlowInterceptor>,
    settings: TunnelSettings,
    stats: TunnelStats,
}

impl Decrypting {
    pub(crate) fn new(
        dispatcher: Arc<Dispatcher>,
        interceptor: Arc<dyn FlowInterceptor>,
        settings: TunnelSettings,
    ) -> Self {
        Self {
            dispatcher,
            interceptor,
            settings,
            stats: TunnelStats::default(),
        }
    }
}

/// The interceptor judges by the port only; a proxy request for a name has
/// no address yet.
fn flow_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::Ip(addr) => *addr,
        TargetAddr::Domain(_, port) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), *port),
    }
}

impl ClientInterceptor for Decrypting {
    fn claim(&self, target: &TargetAddr, first: &[u8]) -> Option<String> {
        self.interceptor.claim(first, flow_addr(target))
    }

    fn serve<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
        host: String,
        stream: BoxStream,
        first: Vec<u8>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            crate::tunnel::bump(&self.stats.mitm_flows);
            let http = sniff::http_request_head(&first);
            let outbound = RequestedTarget {
                dispatcher: &self.dispatcher,
                target,
                host: &host,
                http: http.as_ref(),
                source: client_source(client),
            };
            let flow = InterceptedFlow {
                inbound: stream,
                first,
                host: host.clone(),
                target: flow_addr(target),
            };
            self.interceptor
                .serve(flow, &outbound, &self.settings, &self.stats)
                .await;
        })
    }
}

/// Connects an intercepted flow to what the client asked the proxy for, a
/// name included, instead of the placeholder address the interceptor holds.
struct RequestedTarget<'a> {
    dispatcher: &'a Dispatcher,
    target: &'a TargetAddr,
    host: &'a str,
    http: Option<&'a sniff::HttpRequestHead>,
    source: FlowSource,
}

impl TcpOutbound for RequestedTarget<'_> {
    fn protocol(&self) -> &'static str {
        self.dispatcher.protocol()
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        // A name target is routed by itself; an address target by the host
        // the interceptor read from the flow.
        let host = matches!(self.target, TargetAddr::Ip(_)).then_some(self.host);
        let origin = FlowOrigin {
            process: None,
            source: self.source,
        };
        Box::pin(
            self.dispatcher
                .connect_origin_flow(self.target, host, origin, self.http),
        )
    }
}

/// A proxy client's address and the listener port it reached, for
/// `SRC-IP` and `IN-PORT` rules.
pub(crate) fn client_source(client: ClientAddrs) -> FlowSource {
    FlowSource {
        address: Some(client.peer.ip().to_canonical()),
        in_port: Some(client.local.port()),
    }
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}
