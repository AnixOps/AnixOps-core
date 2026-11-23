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
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound, UdpFlow};
use inbound_mixed::{ClientAddrs, ClientConnector, ClientInterceptor, MixedSettings, MixedStats};
use tokio::sync::oneshot;

use crate::config::RuntimeConfig;
use crate::connections::{Dispatcher, FlowOrigin};
use crate::lan_guard::LanPeer;
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
                    ClientProcess::Local,
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
            // Decrypted connections carry the listener's process name too.
            let interceptor = if decrypt {
                self.decrypting.as_ref().map(|decrypting| {
                    decrypting.for_clients(ClientProcess::Named(crate::replay_proxy::PROCESS_NAME))
                })
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
                // The share names its devices and marks their flows itself.
                self.decrypting.clone(),
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

/// How a proxy listener names its clients' connections for `PROCESS-NAME`
/// rules and the connection list. A listener's connector and its
/// [`Decrypting`] interceptor use the same one, so a connection is routed
/// by the same process whether it is decrypted or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientProcess {
    /// The local process that opened the connection, looked up only when a
    /// `PROCESS-NAME` rule needs it: the desktop local proxy and the packet
    /// tunnel's system proxy listener.
    Local,
    /// The phone's address on the network ([`crate::lan_share::device_label`]);
    /// its flows carry a [`LanPeer`] (see [`crate::lan_guard`]), with
    /// [`LanPeer::block_private_networks`] as the share was started with.
    LanDevice { block_private_networks: bool },
    /// The same name for every connection ([`crate::replay_proxy::PROCESS_NAME`]).
    Named(&'static str),
}

impl ClientProcess {
    async fn name(self, dispatcher: &Dispatcher, client: ClientAddrs) -> Option<String> {
        match self {
            Self::Local if dispatcher.wants_process() => tokio::task::spawn_blocking(move || {
                crate::process::process_name(client.peer, client.local)
            })
            .await
            .ok()
            .flatten(),
            Self::Local => None,
            Self::LanDevice { .. } => Some(crate::lan_share::device_label(client.peer.ip())),
            Self::Named(name) => Some(name.to_string()),
        }
    }

    /// How `client`'s flows are kept from this computer itself: only
    /// another device on the LAN share is a [`LanPeer`].
    fn lan_peer(self, client: ClientAddrs) -> Option<LanPeer> {
        match self {
            Self::LanDevice {
                block_private_networks,
            } => crate::lan_share::lan_peer(client, block_private_networks),
            Self::Local | Self::Named(_) => None,
        }
    }

    /// Connects `client`'s request for `target`, routed by its process, its
    /// address and listener port, and the head of a plain HTTP request in
    /// `first` (for `USER-AGENT` and `URL-REGEX` rules).
    pub(crate) async fn connect(
        self,
        dispatcher: &Dispatcher,
        client: ClientAddrs,
        target: &TargetAddr,
        first: &[u8],
    ) -> io::Result<BoxStream> {
        let process = self.name(dispatcher, client).await;
        let http = sniff::http_request_head(first);
        let origin = FlowOrigin {
            process: process.as_deref(),
            source: client_source(client),
            lan_peer: self.lan_peer(client),
        };
        dispatcher
            .connect_origin_flow(target, None, origin, http.as_ref())
            .await
    }
}

/// Routes each client's connections, naming its local process when a
/// `PROCESS-NAME` rule needs it and passing the head of a plain HTTP request
/// to `USER-AGENT` and `URL-REGEX` rules. The desktop local proxy and the
/// packet tunnel's system proxy listener ([`crate::system_proxy`]) use it.
pub(crate) struct ProcessRouting(pub(crate) Arc<Dispatcher>);

impl ClientConnector for ProcessRouting {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(ClientProcess::Local.connect(&self.0, client, target, &[]))
    }

    fn connect_client_with_first<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
        first: &'a [u8],
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(ClientProcess::Local.connect(&self.0, client, target, first))
    }

    /// SOCKS5 `UDP ASSOCIATE` flows go through the same rules as the packet
    /// tunnel's UDP (routing, `block_quic`, the connection list); the
    /// listener answers it only with [`MixedSettings::udp`] set.
    fn open_client_udp<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.0.open_udp_flow(target, None))
    }
}

/// The config's `mitm` section on a proxy listener: claimed connections go
/// to the same [`FlowInterceptor`] the packet tunnel uses, with the same
/// outbound view ([`Dispatcher::with_requested_target`]), so each decrypted
/// request is routed on its own (`URL-REGEX`, `USER-AGENT`, `REJECT`) as in
/// the tunnel. On the LAN share (`ClientProcess::LanDevice`) every
/// connection it opens, each request's included, carries the device's
/// [`LanPeer`], so DIRECT does not take it to this computer itself (see
/// [`crate::lan_guard`]).
pub struct Decrypting {
    dispatcher: Arc<Dispatcher>,
    interceptor: Arc<dyn FlowInterceptor>,
    settings: TunnelSettings,
    /// Shared by the listeners of one local proxy (its own, the LAN share
    /// and the replay proxy), whose decryption counts as one.
    stats: Arc<TunnelStats>,
    /// How the listener names its clients, as its connector does.
    process: ClientProcess,
}

impl Decrypting {
    pub(crate) fn new(
        dispatcher: Arc<Dispatcher>,
        interceptor: Arc<dyn FlowInterceptor>,
        settings: TunnelSettings,
        process: ClientProcess,
    ) -> Self {
        Self {
            dispatcher,
            interceptor,
            settings,
            stats: Arc::default(),
            process,
        }
    }

    /// The same decryption for another listener, which names its clients
    /// as `process`; the counters stay shared.
    pub(crate) fn for_clients(&self, process: ClientProcess) -> Arc<dyn ClientInterceptor> {
        Arc::new(Self {
            dispatcher: self.dispatcher.clone(),
            interceptor: self.interceptor.clone(),
            settings: self.settings.clone(),
            stats: self.stats.clone(),
            process,
        })
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
            let process = self.process.name(&self.dispatcher, client).await;
            let http = sniff::http_request_head(&first);
            let origin = FlowOrigin {
                process: process.as_deref(),
                source: client_source(client),
                lan_peer: self.process.lan_peer(client),
            };
            // The interceptor holds a placeholder address for a name; the
            // view connects and routes what the client asked for instead.
            let outbound =
                self.dispatcher
                    .with_requested_target(target, &host, http.as_ref(), origin);
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

/// A proxy client's address and the listener port it reached, for
/// `SRC-IP` and `IN-PORT` rules.
pub(crate) fn client_source(client: ClientAddrs) -> FlowSource {
    FlowSource {
        address: Some(client.peer.ip().to_canonical()),
        in_port: Some(client.local.port()),
        port: Some(client.peer.port()),
    }
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}

/// HTTPS decrypted on a proxy listener is routed request by request like
/// in the packet tunnel. Here, not in `tests/`, because the listener is
/// given an engine that trusts a test origin, which a config cannot ask for.
#[cfg(all(test, feature = "mitm"))]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine as _;
    use config_core::routing::RoutingSpec;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::config::MitmConfig;
    use crate::mitm::MitmEngine;
    use crate::routing::RoutedOutbound;
    use crate::system_proxy::{SystemProxy, SystemProxyOptions};

    const HOST: &str = "api.example.test";
    const POLICY: &str = "[Plugin]\n\
name = NetworkCore MITM Test\n\
\n\
[MITM]\n\
enable = true\n\
hostname = api.example.test\n";
    const WAIT: Duration = Duration::from_secs(10);

    struct Root {
        certificate: CertificateDer<'static>,
        key: KeyPair,
        params: CertificateParams,
    }

    fn root(name: &str) -> Root {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key).unwrap().der().clone();
        Root {
            certificate,
            key,
            params,
        }
    }

    fn trusting(root: &CertificateDer<'static>) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    /// A TLS origin for `HOST` behind one node: answers every request with
    /// the node's name and counts the connections opened through it.
    struct NodeOrigin {
        acceptor: tokio_rustls::TlsAcceptor,
        name: &'static str,
        opened: Arc<AtomicUsize>,
    }

    impl NodeOrigin {
        fn new(origin_root: &Root, name: &'static str, opened: Arc<AtomicUsize>) -> Self {
            let key = KeyPair::generate().unwrap();
            let issuer = rcgen::Issuer::from_params(&origin_root.params, &origin_root.key);
            let certificate = CertificateParams::new(vec![HOST.to_string()])
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Self {
                acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                name,
                opened,
            }
        }
    }

    impl TcpOutbound for NodeOrigin {
        fn protocol(&self) -> &'static str {
            "test-origin"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let (near, far) = tokio::io::duplex(64 * 1024);
                let acceptor = self.acceptor.clone();
                let body = self.name.as_bytes();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(far).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            buf.drain(..end + 4);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            );
                            if stream.write_all(response.as_bytes()).await.is_err()
                                || stream.write_all(body).await.is_err()
                                || stream.flush().await.is_err()
                            {
                                return;
                            }
                        }
                    }
                });
                Ok(Box::new(near) as BoxStream)
            })
        }
    }

    async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> (String, String) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < end + 4 + length {
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "response cut short");
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + length]).into_owned();
                return (head, body);
            }
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before a response");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn get(
        app: &mut (impl AsyncRead + AsyncWrite + Unpin),
        path: &str,
        agent: &str,
    ) -> (String, String) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {agent}\r\n\r\n");
        app.write_all(request.as_bytes()).await.unwrap();
        tokio::time::timeout(WAIT, read_response(app))
            .await
            .expect("answered in time")
    }

    /// Requests through the packet tunnel's system proxy listener (the
    /// mixed inbound, as Safari and most apps reach it with the default
    /// takeover) to `authority`, a name or an address: the same rules and
    /// outcomes as `each_decrypted_http1_request_is_routed_on_its_own` in
    /// `tests/mitm.rs` for the tunnel.
    async fn decrypted_requests_are_routed_on_their_own(authority: &str) {
        let device_root = root("NetworkCore Test Device Root");
        let origin_root = root("NetworkCore Test Origin Root");
        let mitm = MitmConfig {
            policy: POLICY.to_string(),
            plugins: Vec::new(),
            ca_certificate: base64::engine::general_purpose::STANDARD
                .encode(&device_root.certificate),
            ca_private_key: base64::engine::general_purpose::STANDARD
                .encode(device_root.key.serialize_der()),
            script_assets: Default::default(),
            resource_assets: Default::default(),
            script_store_path: None,
        };
        let engine = MitmEngine::new(&mitm)
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate));

        let counters: [Arc<AtomicUsize>; 2] = [Arc::default(), Arc::default()];
        let node = |name: &'static str, opened: &Arc<AtomicUsize>| {
            Arc::new(NodeOrigin::new(&origin_root, name, opened.clone())) as Arc<dyn TcpOutbound>
        };
        let nodes = BTreeMap::from([
            ("node-a".to_string(), node("node-a", &counters[0])),
            ("node-b".to_string(), node("node-b", &counters[1])),
        ]);
        let spec = RoutingSpec {
            rules: [
                // Matches only if a flow were routed by the placeholder
                // address the interceptor holds for a name.
                "IP-CIDR,0.0.0.0/8,REJECT,no-resolve",
                r"URL-REGEX,^https://api\.example\.test/video/,node-b",
                "USER-AGENT,Special*,node-b",
                r#"AND,((URL-REGEX,"^https://api\.example\.test/ads/"),(DST-PORT,443)),REJECT"#,
                "FINAL,node-a",
            ]
            .iter()
            .map(|rule| rule.to_string())
            .collect(),
            groups: Vec::new(),
        };
        let direct = node("direct", &Arc::default());
        let routed = RoutedOutbound::new(&spec, direct, nodes).unwrap();
        let dispatcher = Arc::new(Dispatcher::routed(Arc::new(routed)));
        let config = RuntimeConfig::from_json(
            br#"{"schema_version":1,"profile_id":"t","outbound":{"type":"direct"}}"#,
        )
        .unwrap();
        let decrypting = Arc::new(Decrypting::new(
            dispatcher.clone(),
            Arc::new(engine),
            crate::tunnel_settings(&config).unwrap(),
            ClientProcess::Local,
        ));
        let listener = SystemProxy::start(
            dispatcher.clone(),
            Some(decrypting as Arc<dyn ClientInterceptor>),
            SystemProxyOptions {
                port: 0,
                max_connections: 16,
            },
        )
        .unwrap();

        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()));
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
        let mut answer = vec![0u8; ESTABLISHED.len()];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, ESTABLISHED);
        let mut app =
            tokio_rustls::TlsConnector::from(Arc::new(trusting(&device_root.certificate)))
                .connect(ServerName::try_from(HOST).unwrap(), stream)
                .await
                .expect("the listed host is served with a leaf from the device root");

        assert_eq!(get(&mut app, "/index.html", "App").await.1, "node-a");
        // URL-REGEX and USER-AGENT see every decrypted request.
        assert_eq!(get(&mut app, "/video/1.ts", "App").await.1, "node-b");
        assert_eq!(get(&mut app, "/video/2.ts", "App").await.1, "node-b");
        assert_eq!(get(&mut app, "/feed", "SpecialPlayer/2").await.1, "node-b");
        assert_eq!(get(&mut app, "/feed", "App").await.1, "node-a");
        // REJECT answers on the listener and keeps the connection.
        let (head, _) = get(&mut app, "/ads/banner.js", "App").await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        assert_eq!(get(&mut app, "/index.html", "App").await.1, "node-a");
        // One origin connection per switch, none for repeats on one node.
        assert_eq!(counters[0].load(Ordering::SeqCst), 2);
        assert_eq!(counters[1].load(Ordering::SeqCst), 1);
        drop(app);
        drop(listener);
    }

    #[tokio::test]
    async fn decrypted_requests_to_a_name_are_routed_on_their_own() {
        decrypted_requests_are_routed_on_their_own("api.example.test:443").await;
    }

    #[tokio::test]
    async fn decrypted_requests_to_an_address_are_routed_on_their_own() {
        decrypted_requests_are_routed_on_their_own("192.0.2.10:443").await;
    }

    /// The direct outbound of a test: counts the connections it would open.
    struct Direct(NodeOrigin);

    impl TcpOutbound for Direct {
        fn protocol(&self) -> &'static str {
            crate::direct::PROTOCOL
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            self.0.connect(target)
        }
    }

    /// A phone on the LAN share whose decrypted request a `URL-REGEX` rule
    /// sends DIRECT to this computer's loopback is refused like any of its
    /// other flows (`crate::lan_guard`): routing request by request does not
    /// get around the check. Its other requests are still routed on their
    /// own, through the nodes, which resolve the far side.
    #[tokio::test]
    async fn a_phones_decrypted_request_routed_direct_to_loopback_is_refused() {
        let device_root = root("NetworkCore Test Device Root");
        let origin_root = root("NetworkCore Test Origin Root");
        let mitm = MitmConfig {
            policy: POLICY.to_string(),
            plugins: Vec::new(),
            ca_certificate: base64::engine::general_purpose::STANDARD
                .encode(&device_root.certificate),
            ca_private_key: base64::engine::general_purpose::STANDARD
                .encode(device_root.key.serialize_der()),
            script_assets: Default::default(),
            resource_assets: Default::default(),
            script_store_path: None,
        };
        let engine = MitmEngine::new(&mitm)
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate));

        let counters: [Arc<AtomicUsize>; 3] = [Arc::default(), Arc::default(), Arc::default()];
        let node = |name: &'static str, opened: &Arc<AtomicUsize>| {
            Arc::new(NodeOrigin::new(&origin_root, name, opened.clone())) as Arc<dyn TcpOutbound>
        };
        let nodes = BTreeMap::from([
            ("node-a".to_string(), node("node-a", &counters[0])),
            ("node-b".to_string(), node("node-b", &counters[1])),
        ]);
        let spec = RoutingSpec {
            rules: [
                r"URL-REGEX,^https://api\.example\.test/local/,DIRECT",
                r"URL-REGEX,^https://api\.example\.test/video/,node-b",
                "FINAL,node-a",
            ]
            .iter()
            .map(|rule| rule.to_string())
            .collect(),
            groups: Vec::new(),
        };
        let direct = Arc::new(Direct(NodeOrigin::new(
            &origin_root,
            "direct",
            counters[2].clone(),
        )));
        let routed = RoutedOutbound::new(&spec, direct, nodes).unwrap();
        let dispatcher = Arc::new(Dispatcher::routed(Arc::new(routed)));
        let config = RuntimeConfig::from_json(
            br#"{"schema_version":1,"profile_id":"t","outbound":{"type":"direct"}}"#,
        )
        .unwrap();
        let decrypting = Decrypting::new(
            dispatcher.clone(),
            Arc::new(engine),
            crate::tunnel_settings(&config).unwrap(),
            ClientProcess::Local,
        );
        // As the LAN share hands it its devices' connections.
        let interceptor = decrypting.for_clients(ClientProcess::LanDevice {
            block_private_networks: false,
        });
        let phone = ClientAddrs {
            peer: "192.168.1.23:50000".parse().unwrap(),
            local: "192.168.1.5:8899".parse().unwrap(),
        };

        // `CONNECT 127.0.0.1:443`, already answered: the listener hands the
        // interceptor the client's first bytes (the ClientHello) and the rest.
        let (app_io, mut listener_io) = tokio::io::duplex(64 * 1024);
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(trusting(&device_root.certificate)));
        let handshake = tokio::spawn(async move {
            connector
                .connect(ServerName::try_from(HOST).unwrap(), app_io)
                .await
        });
        let mut first = vec![0u8; 64 * 1024];
        let n = tokio::time::timeout(WAIT, listener_io.read(&mut first))
            .await
            .unwrap()
            .unwrap();
        first.truncate(n);
        tokio::spawn(async move {
            let target = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
            interceptor
                .serve(
                    phone,
                    &target,
                    HOST.to_string(),
                    Box::new(listener_io),
                    first,
                )
                .await;
        });
        let mut app = tokio::time::timeout(WAIT, handshake)
            .await
            .unwrap()
            .unwrap()
            .expect("the listed host is served with a leaf from the device root");

        assert_eq!(get(&mut app, "/index.html", "App").await.1, "node-a");
        assert_eq!(get(&mut app, "/video/1.ts", "App").await.1, "node-b");
        let (head, _) = get(&mut app, "/local/admin", "App").await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
        assert_eq!(counters[2].load(Ordering::SeqCst), 0, "DIRECT was dialed");
        assert!(dispatcher
            .tracker()
            .connections()
            .closed
            .iter()
            .any(
                |connection| connection.error == Some(crate::lan_guard::REFUSED)
                    && connection.process.as_deref() == Some("LAN 192.168.1.23")
            ));
    }
}
