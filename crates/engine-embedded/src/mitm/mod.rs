//! HTTPS decryption (MITM) for the packet tunnel, feature `mitm`.
//!
//! The policy text and Loon plugins in the config are imported and merged
//! into one `mitm_anixops` policy; a plugin the policy core refuses is left
//! out. A TCP flow to port 443 whose ClientHello names a host on the merged
//! `[MITM] hostname` list is terminated here with a leaf certificate issued
//! from the device's root (generated and trusted on the Swift side), relayed
//! to the origin over a verifying TLS client, and its HTTP/1.1 messages pass
//! through the same `mitm-policy` / `engine-native` rewrite hook the desktop
//! engines use: URL reject and redirect, header and body rewrites, Map Local.
//! Plain HTTP flows go through the same hook without TLS.
//!
//! Limits that keep the extension inside its memory budget: a body that no
//! body rule or script reads is forwarded as it arrives and only its head is
//! planned. A body a rule reads is held whole up to [`MAX_BODY_BYTES`]; a
//! larger one, `text/event-stream` responses and protocol upgrades stop
//! rewriting for the rest of the connection and are relayed as they are.
//! Requests whose response a rule reads ask for `Accept-Encoding: identity`,
//! so body rules see plain text. An app that offers `h2` gets HTTP/2 when
//! the origin chooses it too; each stream then goes through the same hook
//! and capture (see [`http2`]).
//!
//! Remote `[Map Local]` bodies (and Quantumult X `echo-response` files) are
//! downloaded by the app and named in `resource_assets`; they are read once
//! here and inlined into the plugin before it is imported.
//!
//! With the `scripts` feature, `[Script]` dispatches run in QuickJS from the
//! consented local copies in `script_assets`, on the blocking pool so a
//! script never stalls the tunnel's single-threaded runtime. Each dispatch
//! gets [`SCRIPT_MEMORY_LIMIT_BYTES`] of heap and at most
//! [`SCRIPT_MAX_TIMEOUT_MS`]. `$httpClient` requests go through the tunnel's
//! dispatcher (see `FlowInterceptor::set_script_outbound`), one HTTP/1.1 request
//! per connection with a [`MAX_BODY_BYTES`] answer.
//!
//! Plugin scripts outside HTTP flows (`cron`, `network-changed`, `generic`,
//! Quantumult X `[task_local]`) run from the same consented copies on the
//! tunnel's runtime (see `scheduler`): cron scripts in local time, the others
//! when the client sends the `network_changed` or `run_script` control
//! command. What any script posts with `$notification` waits for the
//! client's `script_notifications` command.

mod http1;
mod http2;
#[cfg(feature = "scripts")]
mod http_client;
pub mod inspect;
pub(crate) mod outcomes;
mod request_route;
#[cfg(feature = "scripts")]
mod scheduler;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use control_domain::{
    GrantedPermissions, HookPoint, HttpMitmPhase, MetadataEntry, MitmHostnameDecision,
    MitmPluginService, PluginInstance, PluginManifest, PluginPackage, PluginPermission,
};
use engine_native::{
    NativeHttpMitmPluginHook, NativePlainHttpMessage, NativePlainHttpRewriteReport,
};
#[cfg(feature = "scripts")]
use engine_native::{NativeQuickJsScriptExecutor, NativeQuickJsScriptRuntimeConfig};
use engine_outbound::reject::{rejection, RejectAction};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use mitm_policy::loon_map_local::MAP_LOCAL_REMOTE_DATA_MAX_BYTES;
use mitm_policy::loon_plugin::{import_loon_plugin_with_resources, merged_plugin_source};
use mitm_policy::{plan_waiting_for_engines, AnixOpsMitmPluginService, CompiledPolicyRelease};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use self::http1::{Body, Conn, Framing, Head};
use self::request_route::{Decision, RequestRoutes};
use crate::capture::stream::SseParser;
use crate::capture::websocket::{Deflate, WsParser};
use crate::capture::Direction;
use crate::capture::{CaptureStore, CapturedBody, HttpExchange};
use crate::config::MitmConfig;
use crate::tunnel::{FlowInterceptor, InterceptedFlow, TunnelSettings, TunnelStats};

pub const PLUGIN_ID: &str = "networkcore.ios.mitm";
/// Largest request or response body the rewrite hook sees.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Body bytes all decrypted connections of one engine hold at once for
/// rules to read: every HTTP/2 connection's share (`MAX_HELD_BODY_BYTES` in
/// the `http2` module) and every HTTP/1.1 body come out of it. A body that
/// finds no room is relayed without rewriting (`busy`) instead of being
/// held, so many connections reading bodies at once cannot add up past it.
#[cfg(not(target_os = "ios"))]
pub const MAX_ENGINE_HELD_BODY_BYTES: usize = 16 * MAX_BODY_BYTES;
/// The iOS total, within the Network Extension's memory limit of about
/// 50 MB: each held body is copied a few more times while it is planned.
#[cfg(target_os = "ios")]
pub const MAX_ENGINE_HELD_BODY_BYTES: usize = 6 * MAX_BODY_BYTES;
/// Plugin texts handed to one tunnel, in total.
const MAX_POLICY_BYTES: usize = 8 * 1024 * 1024;
/// QuickJS heap per script dispatch. A large script gets more (6 bytes per
/// source byte plus 4 MiB), up to the whole [`SCRIPT_MEMORY_BUDGET_BYTES`],
/// so a script of a few MiB parses.
#[cfg(not(target_os = "ios"))]
pub const SCRIPT_MEMORY_LIMIT_BYTES: usize = 8 * 1024 * 1024;
/// QuickJS heap per script dispatch on iOS, where the Network Extension's
/// whole memory limit is about 50 MB and the tunnel, its buffers and
/// capture need their share.
#[cfg(target_os = "ios")]
pub const SCRIPT_MEMORY_LIMIT_BYTES: usize = 6 * 1024 * 1024;
/// Memory of the dispatches running at once, in total: each holds its heap
/// limit plus four times its body
/// (`engine_native::QUICKJS_BODY_COPIES_PER_DISPATCH`). Four ordinary
/// scripts side by side, or one script of a few MiB alone.
#[cfg(not(target_os = "ios"))]
pub const SCRIPT_MEMORY_BUDGET_BYTES: usize = 32 * 1024 * 1024;
/// The iOS total: two ordinary scripts with small bodies side by side, or
/// one with a body near [`MAX_BODY_BYTES`]; a script's heap never exceeds
/// it, so a script above about 2 MiB of source may not parse on iOS.
#[cfg(target_os = "ios")]
pub const SCRIPT_MEMORY_BUDGET_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for a script's own `timeout`.
pub const SCRIPT_MAX_TIMEOUT_MS: usize = 3_000;
const LEAF_CACHE_ENTRIES: usize = 64;
const DECISION_CACHE_ENTRIES: usize = 512;

/// Hostname decisions in two generations of at most half of
/// [`DECISION_CACHE_ENTRIES`] each. A full recent generation becomes the
/// older one and the previous older one is dropped; a host found in the
/// older generation moves back to the recent one. Hosts in use stay cached
/// instead of every host being evaluated again at once.
#[derive(Debug, Default)]
struct DecisionCache {
    recent: HashMap<String, bool>,
    older: HashMap<String, bool>,
}

impl DecisionCache {
    fn get(&mut self, host: &str) -> Option<bool> {
        if let Some(decision) = self.recent.get(host) {
            return Some(*decision);
        }
        let decision = self.older.remove(host)?;
        self.insert(host.to_string(), decision);
        Some(decision)
    }

    fn insert(&mut self, host: String, decision: bool) {
        if !self.recent.contains_key(&host) && self.recent.len() >= DECISION_CACHE_ENTRIES / 2 {
            self.older = std::mem::take(&mut self.recent);
        }
        self.recent.insert(host, decision);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.recent.len() + self.older.len()
    }
}
const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
/// Request methods of a plain HTTP flow that is taken over. `CONNECT` and
/// unknown methods keep their own path.
const PLAIN_HTTP_METHODS: [&str; 8] = [
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ",
];

/// Largest total of downloaded `[Map Local]` bodies read at start.
const MAX_RESOURCE_BYTES: usize = 2 * 1024 * 1024;

/// Reads the downloaded resource files. One that is missing, too large or
/// over the total is skipped: its plugin line is then graded unsupported.
fn read_resource_assets(assets: &BTreeMap<String, String>) -> BTreeMap<String, Vec<u8>> {
    let mut total = 0;
    let mut resources = BTreeMap::new();
    for (url, path) in assets {
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        let len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if len > MAP_LOCAL_REMOTE_DATA_MAX_BYTES || total + len > MAX_RESOURCE_BYTES {
            continue;
        }
        if let Ok(body) = std::fs::read(path) {
            if body.len() <= MAP_LOCAL_REMOTE_DATA_MAX_BYTES {
                total += body.len();
                resources.insert(url.clone(), body);
            }
        }
    }
    resources
}

pub struct MitmEngine {
    service: Arc<AnixOpsMitmPluginService>,
    instance: PluginInstance,
    hook: Arc<NativeHttpMitmPluginHook>,
    /// Whether the hook can run scripts, which must leave the runtime thread.
    scripts: bool,
    /// Where script `$httpClient` requests go: the tunnel's dispatcher, so
    /// they follow the same routing as the device's own connections.
    script_outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    issuer: Issuer<'static, KeyPair>,
    upstream: Arc<ClientConfig>,
    /// `upstream` offering `h2` before `http/1.1`, for apps that offer it.
    upstream_h2: Arc<ClientConfig>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    decisions: Mutex<DecisionCache>,
    /// What decryption did per host, for `mitm_hosts`.
    outcomes: Mutex<outcomes::HostOutcomes>,
    next_request: AtomicU64,
    /// Body bytes held for rules across all connections, see
    /// [`MAX_ENGINE_HELD_BODY_BYTES`].
    held_bodies: Arc<http2::BodyBudget>,
    /// `[Rule]` lines of the accepted plugins, for the routing model.
    plugin_rules: Vec<config_core::routing::RoutingRule>,
    /// Cron, network-change and generic scripts, and the notifications
    /// every script posts.
    #[cfg(feature = "scripts")]
    scheduler: Option<Arc<scheduler::ScriptScheduler>>,
    /// Frees the policy's compiled forms that `mitm_policy` keeps between
    /// messages (hostname engine, idle engines, Map Local, header-block and
    /// jq rules) when this engine goes away. Each engine's policy is a
    /// revision of its own (the serial line below), so without this a
    /// reload would leave the old revision compiled in memory. Last, so it
    /// runs after the hook is dropped.
    _compiled_policy: CompiledPolicyRelease,
}

impl MitmEngine {
    /// Validates the policy and the root. Errors are fixed strings: neither
    /// the policy nor key material reaches them.
    pub fn new(config: &MitmConfig) -> Result<Self, &'static str> {
        let total = config.policy.len() + config.plugins.iter().map(String::len).sum::<usize>();
        if total > MAX_POLICY_BYTES {
            return Err("mitm policy is too large");
        }
        let resources = read_resource_assets(&config.resource_assets);
        let imports = std::iter::once(&config.policy)
            .filter(|policy| !policy.trim().is_empty())
            .chain(&config.plugins)
            .map(|text| {
                import_loon_plugin_with_resources(text, &resources)
                    .map_err(|_| "mitm plugin is invalid")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let accepted = imports
            .iter()
            .filter(|import| import.report.policy_load_error.is_none())
            .collect::<Vec<_>>();
        let mut policy = merged_plugin_source("NetworkCore iOS MITM", &accepted);
        // Loaded policy engines are reused by a fingerprint that samples a
        // large policy; this last line makes each engine's policy distinct.
        static POLICY_SERIAL: AtomicU64 = AtomicU64::new(1);
        policy.push_str(&format!(
            "\n# networkcore policy {}\n",
            POLICY_SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let compiled_policy = CompiledPolicyRelease::new(&policy);
        let plugin_rules = accepted
            .iter()
            .flat_map(|import| import.routing_rules())
            .collect();
        let scheduled_scripts = accepted
            .iter()
            .flat_map(|import| import.scheduled_scripts.iter().cloned())
            .collect::<Vec<_>>();
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(config.ca_certificate.trim())
            .map_err(|_| "mitm ca_certificate is not base64")?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(config.ca_private_key.trim())
            .map_err(|_| "mitm ca_private_key is not base64")?;
        // The Apple apps store X9.63; a desktop root is kept as PKCS#8.
        let pkcs8 = p256_pkcs8_from_x963(&key).unwrap_or(key);
        let key = KeyPair::try_from(pkcs8.as_slice())
            .map_err(|_| "mitm ca_private_key is not a P-256 key")?;
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(certificate), key)
            .map_err(|_| "mitm ca_certificate is not a certificate")?;

        let service = Arc::new(AnixOpsMitmPluginService::new());
        let package = PluginPackage {
            manifest: PluginManifest {
                id: PLUGIN_ID.to_string(),
                version: "1".to_string(),
                permissions: vec![
                    PluginPermission::ReadRequest,
                    PluginPermission::ModifyRequest,
                    PluginPermission::ReadResponse,
                    PluginPermission::ModifyResponse,
                ],
                hooks: vec![HookPoint::Request, HookPoint::Response],
            },
            source: policy,
        };
        let instance = service
            .load(
                &package,
                &GrantedPermissions {
                    permissions: package.manifest.permissions.clone(),
                },
            )
            .map_err(|_| "mitm policy is invalid")?;
        let upstream = Arc::new(
            transport_tls::client_config(&transport_tls::TlsSettings {
                server_name: String::new(),
                alpn: vec!["http/1.1".to_string()],
                insecure: false,
                ..transport_tls::TlsSettings::default()
            })
            .map_err(|_| "mitm upstream TLS is unavailable")?,
        );
        let upstream_h2 = Arc::new(with_h2((*upstream).clone()));
        let script_outbound = Arc::new(OnceLock::new());
        let hook = NativeHttpMitmPluginHook::new(instance.clone(), service.clone());
        let scripts = !config.script_assets.is_empty();
        let (hook, executor) = if scripts {
            with_scripts(hook, config, &script_outbound, &upstream)?
        } else {
            (hook, None)
        };
        #[cfg(feature = "scripts")]
        let scheduler = executor
            .map(|executor| Arc::new(scheduler::ScriptScheduler::new(executor, scheduled_scripts)));
        #[cfg(not(feature = "scripts"))]
        let _ = (executor, scheduled_scripts);
        Ok(Self {
            service,
            instance,
            hook: Arc::new(hook),
            scripts,
            script_outbound,
            issuer,
            upstream,
            upstream_h2,
            leaves: Mutex::new(HashMap::new()),
            decisions: Mutex::new(DecisionCache::default()),
            outcomes: Mutex::new(outcomes::HostOutcomes::default()),
            next_request: AtomicU64::new(1),
            held_bodies: Arc::new(http2::BodyBudget::new(MAX_ENGINE_HELD_BODY_BYTES)),
            plugin_rules,
            #[cfg(feature = "scripts")]
            scheduler,
            _compiled_policy: compiled_policy,
        })
    }

    /// Runs the rewrite hook. Script dispatches block, so with scripts the
    /// plan runs on the blocking pool, where planning may wait for one of
    /// the policy's loaded engines instead of loading the whole policy again
    /// for each parallel message ([`plan_waiting_for_engines`]).
    async fn plan(
        &self,
        message: NativePlainHttpMessage,
    ) -> io::Result<NativePlainHttpRewriteReport> {
        if !self.scripts {
            return Ok(self.hook.plan_plain_http(&message));
        }
        let hook = self.hook.clone();
        tokio::task::spawn_blocking(move || {
            plan_waiting_for_engines(|| hook.plan_plain_http(&message))
        })
        .await
        .map_err(|_| io::Error::other("mitm rewrite failed"))
    }

    /// Replaces the verifying upstream client, e.g. to trust a test origin.
    pub fn with_upstream_config(mut self, config: ClientConfig) -> Self {
        self.upstream_h2 = Arc::new(with_h2(config.clone()));
        self.upstream = Arc::new(config);
        self
    }

    /// The id the rewrite hook gets for the next request.
    fn next_request_id(&self) -> String {
        self.next_request
            .fetch_add(1, Ordering::Relaxed)
            .to_string()
    }

    fn note_failure(&self, host: &str, failure: outcomes::Failure) {
        if let Ok(mut table) = self.outcomes.lock() {
            table.failed(host, failure, crate::capture::unix_millis());
        }
    }

    fn note_decrypted(&self, host: &str) {
        if let Ok(mut table) = self.outcomes.lock() {
            table.decrypted(host, crate::capture::unix_millis());
        }
    }

    /// The `mitm_hosts` answer: what decryption did per host, the most
    /// recently seen first.
    pub fn hosts_json(&self) -> serde_json::Value {
        let hosts = self
            .outcomes
            .lock()
            .map(|table| table.snapshot())
            .unwrap_or_default();
        serde_json::json!({ "enabled": true, "hosts": hosts })
    }

    /// Forgets what `mitm_hosts` reports.
    pub fn clear_hosts(&self) {
        if let Ok(mut table) = self.outcomes.lock() {
            table.clear();
        }
    }

    /// Whether TLS to `host` is intercepted.
    pub fn intercepts(&self, host: &str) -> bool {
        if let Some(decision) = self
            .decisions
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(host))
        {
            return decision;
        }
        let decision = matches!(
            self.service
                .evaluate_mitm_hostname(&self.instance, host, false),
            Ok(MitmHostnameDecision::Intercept)
        );
        if let Ok(mut cache) = self.decisions.lock() {
            cache.insert(host.to_string(), decision);
        }
        decision
    }

    /// The leaf for `host`, offering `h2` when the origin chose it and
    /// `http/1.1` otherwise.
    fn leaf_config(&self, host: &str, h2: bool) -> io::Result<Arc<ServerConfig>> {
        let config = self.leaf_config_h1(host)?;
        if !h2 {
            return Ok(config);
        }
        let mut config = (*config).clone();
        config.alpn_protocols = vec![http2::ALPN_H2.to_vec()];
        Ok(Arc::new(config))
    }

    fn leaf_config_h1(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        if let Some(config) = self
            .leaves
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).cloned())
        {
            return Ok(config);
        }
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|_| invalid("leaf certificate name is invalid"))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(397);
        let key = KeyPair::generate().map_err(|_| invalid("leaf key generation failed"))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| invalid("leaf certificate signing failed"))?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| invalid("leaf TLS configuration failed"))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .map_err(|_| invalid("leaf TLS configuration failed"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if let Ok(mut cache) = self.leaves.lock() {
            if cache.len() >= LEAF_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(host.to_string(), config.clone());
        }
        Ok(config)
    }

    /// Connects to the origin through `outbound`, terminates the client's
    /// TLS and relays HTTP/1.1 or HTTP/2 (whichever the origin chose among
    /// the client's offers, see [`http2`]) through the rewrite hook until
    /// either side closes.
    /// A plain HTTP flow is relayed as it is, without TLS on either side.
    /// A keep-alive client that sends nothing for `idle_timeout` is closed.
    ///
    /// With capture on, the requests and responses are filed under the
    /// connection `outbound` opened to the origin (see [`crate::capture`]).
    pub async fn serve_flow(
        &self,
        flow: InterceptedFlow,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        crate::capture::scope(self.serve_captured_flow(
            flow,
            outbound,
            connect_timeout,
            idle_timeout,
        ))
        .await
    }

    async fn serve_captured_flow(
        &self,
        flow: InterceptedFlow,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        if !is_tls(&flow.first) {
            return self
                .serve_plain_flow(flow, outbound, connect_timeout, idle_timeout)
                .await;
        }
        let host = flow.host.as_str();
        let target = TargetAddr::Ip(flow.target);
        // The origin answers first, so the app is offered the protocol the
        // origin chose and no request is translated between versions.
        let offers_h2 = http2::offers_h2(&crate::sniff::client_hello_alpn(&flow.first));
        let origin = self
            .connect_origin(host, &target, offers_h2, outbound, connect_timeout)
            .await;
        let h2 = origin
            .as_ref()
            .is_ok_and(|origin| origin.get_ref().1.alpn_protocol() == Some(http2::ALPN_H2));

        let acceptor = tokio_rustls::TlsAcceptor::from(self.leaf_config(host, h2)?);
        let accepted = tokio::time::timeout(
            connect_timeout,
            acceptor.accept(Prefixed::new(flow.inbound, flow.first)),
        )
        .await
        .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
        let client = match accepted {
            Ok(client) => client,
            Err(error) => {
                self.note_failure(host, outcomes::Failure::client(&error));
                return Err(error);
            }
        };
        // An unreachable origin still gets the app a decrypted connection
        // (closed right away), as before origin-first ALPN, so the app sees
        // the usual leaf instead of a failed handshake. A REJECT-TINYGIF
        // rule answers its request with the GIF instead.
        let origin = match origin {
            Ok(origin) => origin,
            Err(error) if rejection(&error) == Some(RejectAction::TinyGif) => {
                return answer_tiny_gif(Conn::new(client, Vec::new()), idle_timeout).await;
            }
            Err(error) => {
                // A REJECT rule is not a decryption failure.
                if rejection(&error).is_none() {
                    self.note_failure(host, outcomes::Failure::origin(&error));
                }
                return Err(error);
            }
        };
        self.note_decrypted(host);

        let authority = authority(host, flow.target.port(), HTTPS_PORT);
        let routes = RequestRoutes::new(outbound, &target).await;
        let reroute = Reroute {
            routes,
            tls_host: Some(host),
            connect_timeout,
        };
        if h2 {
            return self
                .relay_h2(client, origin, host, &authority, idle_timeout, reroute)
                .await;
        }
        self.relay(
            Conn::new(client, Vec::new()),
            Conn::new(Box::new(origin) as BoxStream, Vec::new()),
            "https",
            &authority,
            idle_timeout,
            reroute,
        )
        .await
    }

    /// Opens an origin connection for `head` through the outbound its
    /// request routes to (see [`request_route`]): TLS to `tls_host`
    /// offering `h2` and `http/1.1`, or `http/1.1` alone, as `h2` says, or
    /// plain without a host. An `h2` connection the origin did not accept
    /// `h2` on fails.
    async fn connect_routed(
        &self,
        reroute: &Reroute<'_>,
        routes: &RequestRoutes<'_>,
        head: &engine_outbound::sniff::HttpRequestHead,
        h2: bool,
    ) -> io::Result<BoxStream> {
        let timeout = reroute.connect_timeout;
        let timed_out = |_| io::Error::from(io::ErrorKind::TimedOut);
        let remote = tokio::time::timeout(
            timeout,
            routes.router().connect_request(&routes.target, head),
        )
        .await
        .map_err(timed_out)??;
        let Some(host) = reroute.tls_host else {
            return Ok(remote);
        };
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| invalid("invalid server name"))?;
        let upstream = if h2 {
            self.upstream_h2.clone()
        } else {
            self.upstream.clone()
        };
        let tls = tokio::time::timeout(
            timeout,
            tokio_rustls::TlsConnector::from(upstream).connect(server_name, remote),
        )
        .await
        .map_err(timed_out)??;
        if h2 && tls.get_ref().1.alpn_protocol() != Some(http2::ALPN_H2) {
            return Err(invalid("origin did not accept h2"));
        }
        Ok(Box::new(tls))
    }

    /// Opens the TLS connection to the origin, offering `h2` only when the
    /// app offered it.
    async fn connect_origin(
        &self,
        host: &str,
        target: &TargetAddr,
        offers_h2: bool,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
    ) -> io::Result<tokio_rustls::client::TlsStream<BoxStream>> {
        let remote = tokio::time::timeout(connect_timeout, outbound.connect(target))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| invalid("invalid server name"))?;
        let upstream = if offers_h2 {
            self.upstream_h2.clone()
        } else {
            self.upstream.clone()
        };
        tokio::time::timeout(
            connect_timeout,
            tokio_rustls::TlsConnector::from(upstream).connect(server_name, remote),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    /// Relays a plain HTTP flow through the rewrite hook, so `http://`
    /// rewrites and scripts apply as they do in Loon and Surge.
    async fn serve_plain_flow(
        &self,
        flow: InterceptedFlow,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        let target = TargetAddr::Ip(flow.target);
        let origin = match tokio::time::timeout(connect_timeout, outbound.connect(&target))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        {
            Ok(origin) => origin,
            Err(error) if rejection(&error) == Some(RejectAction::TinyGif) => {
                return answer_tiny_gif(Conn::new(flow.inbound, flow.first), idle_timeout).await;
            }
            Err(error) => return Err(error),
        };
        let authority = authority(&flow.host, flow.target.port(), HTTP_PORT);
        let reroute = Reroute {
            routes: RequestRoutes::new(outbound, &target).await,
            tls_host: None,
            connect_timeout,
        };
        self.relay(
            Conn::new(flow.inbound, flow.first),
            Conn::new(origin, Vec::new()),
            "http",
            &authority,
            idle_timeout,
            reroute,
        )
        .await
    }

    async fn relay<C>(
        &self,
        mut client: Conn<C>,
        mut origin: Conn<BoxStream>,
        scheme: &str,
        authority: &str,
        idle_timeout: Duration,
        reroute: Reroute<'_>,
    ) -> io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        // The connection to the origin is open: with capture on, its HTTP
        // messages are kept instead of its re-encrypted bytes.
        let capture = crate::capture::current_flow();
        // The outbound `origin` goes through, when requests are routed.
        let mut current_route = reroute
            .routes
            .as_ref()
            .map(|routes| routes.connection.clone())
            .unwrap_or_default();
        loop {
            let Ok(request) = tokio::time::timeout(idle_timeout, client.read_head()).await else {
                return Ok(());
            };
            let request = match request {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(()),
                // A head this relay cannot read goes on as it came (its
                // bytes are still buffered) and the connection is relayed
                // unchanged from here, as it would be without decryption.
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    return passthrough(client, origin).await;
                }
                Err(error) => return Err(error),
            };
            let parsed = match (split_request_line(&request.start_line), request.framing()) {
                (Ok(line), Ok(framing)) => Some((line, framing)),
                _ => None,
            };
            let Some(((method, path, version), request_framing)) = parsed else {
                // A request this relay does not rewrite (an unknown framing,
                // a target that is not a path) goes on unchanged, and so
                // does the rest of the connection.
                origin.write_all(&request.encode()).await?;
                return passthrough(client, origin).await;
            };
            let url = format!("{scheme}://{authority}{path}");
            // Filed when this iteration ends, whichever way it ends.
            let mut recording = capture.as_ref().map(|capture| {
                let mut recording = Recording::new(capture, &method, &url, &request.headers);
                recording.publish();
                recording
            });
            if let Some(routes) = &reroute.routes {
                let head = request_route::request_head(&url, request.header("User-Agent"));
                match routes.decide(&current_route, &head).await {
                    Decision::Keep => {}
                    Decision::Reject => {
                        // The body is never read, so the connection cannot
                        // carry another request after one.
                        let close = request.has_token("Connection", "close")
                            || version == "HTTP/1.0"
                            || !matches!(request_framing, Framing::Length(0));
                        let response = response_head(403, &[], None, 0, close);
                        if let Some(recording) = &mut recording {
                            recording.response(&response, &[], Some("rejected"));
                        }
                        client.write_all(&response.encode()).await?;
                        if close {
                            return Ok(());
                        }
                        continue;
                    }
                    Decision::Switch(name) => {
                        match self.connect_routed(&reroute, routes, &head, false).await {
                            Ok(stream) => {
                                origin = Conn::new(stream, Vec::new());
                                current_route = name;
                            }
                            Err(_) => {
                                let response = response_head(502, &[], None, 0, true);
                                if let Some(recording) = &mut recording {
                                    recording.response(&response, &[], Some("connect_failed"));
                                }
                                client.write_all(&response.encode()).await?;
                                return Ok(());
                            }
                        }
                    }
                }
            }
            // A body no rule reads is forwarded as it arrives, not held whole.
            let stream_request = !self.needs_body(&url, HttpMitmPhase::Request);
            let stream_response = !self.needs_body(&url, HttpMitmPhase::Response);
            // What this exchange holds of the engine's body budget, until
            // the exchange ends (the request body is kept for the response
            // phase).
            let mut request_held = http2::Held::new(&self.held_bodies);
            let request_body = if stream_request {
                Vec::new()
            } else {
                if !request_held.grow(body_reservation(request_framing)) {
                    // No room to hold the body: it is relayed as it is.
                    if let Some(recording) = &mut recording {
                        recording.exchange.note = Some("busy");
                        recording.exchange.rules_skipped = true;
                    }
                    origin.write_all(&request.encode()).await?;
                    return passthrough(client, origin).await;
                }
                match client.read_body(request_framing, MAX_BODY_BYTES).await? {
                    Body::Complete(body) => {
                        if let Some(recording) = &mut recording {
                            recording.exchange.request_body = CapturedBody::of(&body);
                        }
                        body
                    }
                    Body::TooLarge { raw, body, size } => {
                        if let Some(recording) = &mut recording {
                            recording.exchange.request_body = CapturedBody { data: body, size };
                            recording.exchange.note = Some("too_large");
                            recording.exchange.rules_skipped = true;
                        }
                        origin.write_all(&request.encode()).await?;
                        origin.write_all(&raw).await?;
                        return passthrough(client, origin).await;
                    }
                }
            };
            let request_id = self.next_request_id();
            let report = self
                .plan(NativePlainHttpMessage {
                    request_id: request_id.clone(),
                    url: url.clone(),
                    method: Some(method.clone()),
                    phase: HttpMitmPhase::Request,
                    status_code: None,
                    headers: to_metadata(&request.headers),
                    body: request_body,
                    request_headers: Vec::new(),
                    request_body: None,
                })
                .await?;
            let client_close = request.has_token("Connection", "close") || version == "HTTP/1.0";
            let had_body = !matches!(request_framing, Framing::Length(0));

            if report.terminal_action.is_some() {
                // A streamed body was never read, so the connection cannot
                // carry another request after this answer.
                let close = client_close || (stream_request && had_body);
                let response = response_head(
                    report.final_status_code.unwrap_or(200),
                    &report.headers,
                    report.redirect_location.as_deref(),
                    report.body.len(),
                    close,
                );
                // A HEAD answer keeps the Content-Length a GET would get
                // and carries no body (RFC 9110 9.3.2).
                let body: &[u8] = if method.eq_ignore_ascii_case("HEAD") {
                    &[]
                } else {
                    &report.body
                };
                if let Some(recording) = &mut recording {
                    recording.response(&response, body, Some("answered_locally"));
                }
                client.write_all(&response.encode()).await?;
                client.write_all(body).await?;
                if close {
                    return Ok(());
                }
                continue;
            }

            // A rewrite may change the path; the authority stays the
            // intercepted host.
            let path = report
                .url
                .strip_prefix(&format!("{scheme}://{authority}"))
                .filter(|rest| rest.starts_with('/'))
                .unwrap_or(path.as_str())
                .to_string();
            let mut headers = from_metadata(&report.headers);
            if stream_request {
                keep_streamed_body_headers(&mut headers, &request.headers);
            } else {
                remove(&mut headers, "Transfer-Encoding");
                remove(&mut headers, "Content-Length");
                if had_body || !report.body.is_empty() {
                    headers.push(("Content-Length".to_string(), report.body.len().to_string()));
                }
            }
            if !stream_response {
                // Rules read the response body as sent, so ask for it
                // uncompressed.
                remove(&mut headers, "Accept-Encoding");
                headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
            }
            let upstream_request = Head {
                start_line: format!("{method} {path} HTTP/1.1"),
                headers,
            };
            origin.write_all(&upstream_request.encode()).await?;
            if stream_request {
                if recording.is_some() {
                    client.start_tap(crate::capture::MAX_HTTP_BODY_BYTES);
                }
                client.copy_body(request_framing, &mut origin).await?;
                if let (Some(recording), Some((data, size))) = (&mut recording, client.take_tap()) {
                    recording.exchange.request_body = CapturedBody { data, size };
                }
            } else {
                origin.write_all(&report.body).await?;
            }
            // The request as the rules and request scripts left it, for the
            // `$request` of response scripts; its body only when it was held.
            let sent_headers = report.headers;
            let sent_body = (!stream_request).then_some(report.body);

            // Interim 1xx responses go straight to the client.
            let (response, status) = loop {
                let head = tokio::time::timeout(idle_timeout, origin.read_head())
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
                let head = match head {
                    Ok(Some(head)) => head,
                    Ok(None) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    // A response head this relay cannot read (its bytes are
                    // still buffered) goes to the app as it came, and the
                    // connection is relayed unchanged from here.
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        if let Some(recording) = &mut recording {
                            recording.unparsed();
                        }
                        return passthrough(client, origin).await;
                    }
                    Err(error) => return Err(error),
                };
                let Ok(status) = response_status(&head.start_line) else {
                    // Not HTTP/1.x (`ICY 200 OK` of an internet radio
                    // stream): relayed unchanged.
                    if let Some(recording) = &mut recording {
                        recording.unparsed();
                    }
                    client.write_all(&head.encode()).await?;
                    return passthrough(client, origin).await;
                };
                if (100..200).contains(&status) && status != 101 {
                    client.write_all(&head.encode()).await?;
                    continue;
                }
                break (head, status);
            };
            let streaming = status == 101
                || response.header("Content-Type").is_some_and(|value| {
                    value.to_ascii_lowercase().starts_with("text/event-stream")
                });
            if streaming {
                let event_stream = status != 101;
                if let Some(recording) = &mut recording {
                    recording.response(&response, &[], None);
                    recording.stream(!stream_response);
                    if event_stream {
                        recording.start_events();
                    } else {
                        recording.publish();
                    }
                }
                client.write_all(&response.encode()).await?;
                if !event_stream {
                    let websocket = response.has_token("Upgrade", "websocket");
                    let sink = recording.as_ref().and_then(Recording::sink);
                    return match sink.filter(|_| websocket) {
                        Some(sink) => {
                            let deflate = response
                                .header("Sec-WebSocket-Extensions")
                                .and_then(Deflate::from_response);
                            relay_websocket(client, origin, sink, deflate).await
                        }
                        None => passthrough(client, origin).await,
                    };
                }
                let Some(recording) = recording.as_mut().filter(|r| r.reads_events()) else {
                    return passthrough(client, origin).await;
                };
                // The events are read as the body is relayed in its framing.
                let framing =
                    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
                        Framing::Length(0)
                    } else if response.header("Transfer-Encoding").is_none()
                        && response.header("Content-Length").is_none()
                    {
                        Framing::UntilClose
                    } else {
                        response.framing()?
                    };
                origin
                    .copy_body_observed(framing, &mut client, |bytes| {
                        recording.response_bytes(bytes)
                    })
                    .await?;
                if client_close
                    || framing == Framing::UntilClose
                    || response.has_token("Connection", "close")
                {
                    return Ok(());
                }
                continue;
            }
            let no_body = method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304;
            let framing = if no_body {
                Ok(Framing::Length(0))
            } else if response.header("Transfer-Encoding").is_none()
                && response.header("Content-Length").is_none()
            {
                Ok(Framing::UntilClose)
            } else {
                response.framing()
            };
            let Ok(framing) = framing else {
                // Lengths that disagree, or a transfer coding nobody can
                // read: the end of this response is unknown, so the app
                // gets a 502 and the connection closes (RFC 9112 section
                // 6.3).
                let head = response_head(502, &[], None, 0, true);
                if let Some(recording) = &mut recording {
                    recording.response(&head, &[], Some("unparsed"));
                }
                client.write_all(&head.encode()).await?;
                return Ok(());
            };
            let close = client_close
                || framing == Framing::UntilClose
                || response.has_token("Connection", "close");

            if stream_response && !no_body {
                // Only the head is planned; the body follows as it arrives.
                let report = self
                    .plan(NativePlainHttpMessage {
                        request_id,
                        url,
                        method: Some(method.clone()),
                        phase: HttpMitmPhase::Response,
                        status_code: Some(status),
                        headers: to_metadata(&response.headers),
                        body: Vec::new(),
                        request_headers: sent_headers,
                        request_body: sent_body,
                    })
                    .await?;
                if report.terminal_action.is_some() {
                    let head = response_head(
                        report.final_status_code.unwrap_or(status),
                        &report.headers,
                        report.redirect_location.as_deref(),
                        report.body.len(),
                        true,
                    );
                    if let Some(recording) = &mut recording {
                        recording.response(&head, &report.body, Some("answered_locally"));
                    }
                    client.write_all(&head.encode()).await?;
                    client.write_all(&report.body).await?;
                    return Ok(());
                }
                let final_status = report.final_status_code.unwrap_or(status);
                let mut headers = from_metadata(&report.headers);
                keep_streamed_body_headers(&mut headers, &response.headers);
                let head = Head {
                    start_line: format!("HTTP/1.1 {final_status} {}", reason(final_status)),
                    headers,
                };
                client.write_all(&head.encode()).await?;
                if let Some(recording) = &mut recording {
                    recording.response(&head, &[], None);
                    origin.start_tap(crate::capture::MAX_HTTP_BODY_BYTES);
                }
                origin.copy_body(framing, &mut client).await?;
                if let (Some(recording), Some((data, size))) = (&mut recording, origin.take_tap()) {
                    recording.exchange.response_body = CapturedBody { data, size };
                }
                if close {
                    return Ok(());
                }
                continue;
            }

            let mut response_headers = response.headers.clone();
            let reservation = response_body_reservation(
                no_body,
                response.header("Content-Encoding").is_some(),
                framing,
            );
            let mut response_held = http2::Held::new(&self.held_bodies);
            if !response_held.grow(reservation) {
                // No room to hold the body: it is relayed as it is.
                if let Some(recording) = &mut recording {
                    recording.response(&response, &[], Some("busy"));
                    recording.exchange.rules_skipped = true;
                }
                client.write_all(&response.encode()).await?;
                return passthrough(client, origin).await;
            }
            let response_body = match origin.read_body(framing, MAX_BODY_BYTES).await? {
                Body::Complete(body) => decoded_for_rules(&mut response_headers, body),
                Body::TooLarge { raw, body, size } => {
                    if let Some(recording) = &mut recording {
                        recording.response(&response, &[], Some("too_large"));
                        recording.exchange.response_body = CapturedBody { data: body, size };
                        recording.exchange.rules_skipped = true;
                    }
                    client.write_all(&response.encode()).await?;
                    client.write_all(&raw).await?;
                    return passthrough(client, origin).await;
                }
            };
            let report = self
                .plan(NativePlainHttpMessage {
                    request_id,
                    url,
                    method: Some(method.clone()),
                    phase: HttpMitmPhase::Response,
                    status_code: Some(status),
                    headers: to_metadata(&response_headers),
                    body: response_body,
                    request_headers: sent_headers,
                    request_body: sent_body,
                })
                .await?;
            let mut head = response_head(
                report.final_status_code.unwrap_or(status),
                &report.headers,
                report.redirect_location.as_deref(),
                report.body.len(),
                close,
            );
            if no_body {
                // Keep the origin's framing headers for HEAD, 204 and 304.
                head = Head {
                    start_line: head.start_line,
                    headers: from_metadata(&report.headers),
                };
            }
            if let Some(recording) = &mut recording {
                let body: &[u8] = if no_body { &[] } else { &report.body };
                recording.response(&head, body, None);
            }
            client.write_all(&head.encode()).await?;
            if !no_body {
                client.write_all(&report.body).await?;
            }
            if close {
                return Ok(());
            }
        }
    }

    /// Whether a rule reads the body of `url`'s messages in `phase`; when
    /// unsure, it does.
    fn needs_body(&self, url: &str, phase: HttpMitmPhase) -> bool {
        self.service
            .needs_body(&self.instance, url, phase)
            .unwrap_or(true)
    }
}

impl FlowInterceptor for MitmEngine {
    /// Script `$httpClient` requests go through `outbound`, set once; until
    /// it is set they fail with an error the script sees.
    fn set_script_outbound(&self, outbound: Arc<dyn TcpOutbound>) {
        let _ = self.script_outbound.set(outbound);
    }

    fn plugin_rules(&self) -> Vec<config_core::routing::RoutingRule> {
        self.plugin_rules.clone()
    }

    #[cfg(feature = "scripts")]
    fn background(self: Arc<Self>) -> Option<BoxFuture<'static, ()>> {
        let scheduler = self
            .scheduler
            .clone()
            .filter(|scheduler| scheduler.has_scripts())?;
        Some(Box::pin(scheduler.run()))
    }

    fn mitm_hosts(&self, clear: bool) -> Option<serde_json::Value> {
        if clear {
            self.clear_hosts();
        }
        Some(self.hosts_json())
    }

    #[cfg(feature = "scripts")]
    fn script_control(&self, request: &crate::control::ScriptControl) -> Option<serde_json::Value> {
        Some(self.scheduler.as_ref()?.control(request))
    }

    /// HTTPS to a `[MITM]` host is decrypted. Plain HTTP needs no
    /// certificate, so every plain request is relayed through the rewrite
    /// hook, as Loon and Surge apply `http://` rules without a hostname.
    fn claim(&self, first: &[u8], target: SocketAddr) -> Option<String> {
        if is_tls(first) {
            if target.port() != HTTPS_PORT {
                return None;
            }
            let host = crate::sniff::client_hello_server_name(first)?;
            return self.intercepts(&host).then_some(host);
        }
        plain_http_host(first)
    }

    /// QUIC to a `[MITM]` host would pass by decryption, so it is refused
    /// and the app falls back to TCP (HTTP/2 or HTTP/1.1), where it is
    /// decrypted. QUIC itself is not terminated.
    fn refuses_quic(&self, host: &str) -> bool {
        self.intercepts(host)
    }

    fn serve<'a>(
        &'a self,
        flow: InterceptedFlow,
        outbound: &'a dyn TcpOutbound,
        settings: &'a TunnelSettings,
        stats: &'a TunnelStats,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let served = self
                .serve_flow(
                    flow,
                    outbound,
                    settings.connect_timeout,
                    settings.idle_timeout,
                )
                .await;
            if served.is_err() {
                crate::tunnel::bump(&stats.mitm_failed);
            }
        })
    }
}

/// How a decrypted connection routes its requests one by one (see
/// [`request_route`]).
struct Reroute<'a> {
    /// `None` when no rule looks at requests.
    routes: Option<RequestRoutes<'a>>,
    /// The server name of an HTTPS origin; `None` for plain HTTP.
    tls_host: Option<&'a str>,
    connect_timeout: Duration,
}

/// Answers the first request of a decrypted flow a `REJECT-TINYGIF` rule
/// refused with a 1x1 GIF, then closes it (the response says so).
async fn answer_tiny_gif<C: AsyncRead + AsyncWrite + Unpin>(
    mut client: Conn<C>,
    idle_timeout: Duration,
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let Ok(head) = tokio::time::timeout(idle_timeout, client.read_head()).await else {
        return Ok(());
    };
    if head?.is_none() {
        return Ok(());
    }
    client
        .write_all(&engine_outbound::reject::tiny_gif_response())
        .await?;
    let (mut io, _) = client.into_parts();
    let _ = io.shutdown().await;
    Ok(())
}

/// One decrypted exchange being captured: filed under its connection as
/// soon as its request head is read (in progress), refreshed when its
/// response starts streaming and finished when dropped, so every way out of
/// the relay loop keeps what was seen.
struct Recording<'a> {
    capture: &'a (Arc<CaptureStore>, u64),
    exchange: HttpExchange,
    /// Its index under the connection once filed.
    filed: Option<usize>,
    /// Splits an event-stream response into events as it is relayed.
    events: Option<SseParser>,
}

impl<'a> Recording<'a> {
    fn new(
        capture: &'a (Arc<CaptureStore>, u64),
        method: &str,
        url: &str,
        headers: &[(String, String)],
    ) -> Self {
        Self {
            capture,
            exchange: HttpExchange::new(
                &http1::display(method),
                &http1::display(url),
                &http1::display_headers(headers),
            ),
            filed: None,
            events: None,
        }
    }

    /// The response could not be read and the connection is relayed
    /// unchanged from here: no rule ran on it.
    fn unparsed(&mut self) {
        self.exchange.note = Some("unparsed");
        self.exchange.rules_skipped = true;
    }

    /// Files the exchange as it stands, still in progress, or refreshes
    /// what the store holds of it.
    fn publish(&mut self) {
        let (store, id) = self.capture;
        match self.filed {
            Some(index) => store.update_exchange(*id, index, &self.exchange),
            None => self.filed = store.open_exchange(*id, self.exchange.clone()),
        }
    }

    /// The response streams from here on (an event stream or an upgrade)
    /// and is relayed as it arrives; `rules_skipped` when a body rule
    /// matched it and so did not run.
    fn stream(&mut self, rules_skipped: bool) {
        self.exchange.note = Some("streaming");
        self.exchange.rules_skipped |= rules_skipped;
    }

    /// The streaming response is an event stream whose head is recorded:
    /// its events are kept from here on, unless a content coding hides
    /// them. Publishes the exchange either way.
    fn start_events(&mut self) {
        let coded = self.exchange.response_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding")
                && !value.trim().eq_ignore_ascii_case("identity")
        });
        if !coded {
            self.events = Some(SseParser::default());
        }
        self.publish();
    }

    /// Where the messages of this exchange's stream go, once it is filed.
    fn sink(&self) -> Option<MessageSink> {
        let (store, id) = self.capture;
        self.filed.map(|index| MessageSink {
            store: store.clone(),
            id: *id,
            index,
        })
    }

    /// Whether [`Recording::response_bytes`] reads the body.
    fn reads_events(&self) -> bool {
        self.events.is_some()
    }

    /// Body bytes of a streaming response as relayed to the app.
    fn response_bytes(&mut self, bytes: &[u8]) {
        let (Some(parser), Some(index)) = (&mut self.events, self.filed) else {
            return;
        };
        let (store, id) = self.capture;
        for event in parser.feed(bytes, crate::capture::unix_millis()) {
            store.push_message(*id, index, event);
        }
    }

    /// The response as the client got it: `head` and the first bytes of
    /// `body`.
    fn response(&mut self, head: &Head, body: &[u8], note: Option<&'static str>) {
        self.exchange.status = response_status(&head.start_line).ok();
        self.exchange.response_headers = http1::display_headers(&head.headers);
        self.exchange.response_body = CapturedBody::of(body);
        if note.is_some() {
            self.exchange.note = note;
        }
    }
}

impl Drop for Recording<'_> {
    fn drop(&mut self) {
        let (store, id) = self.capture;
        let exchange = std::mem::take(&mut self.exchange);
        match self.filed {
            Some(index) => store.finish_exchange(*id, index, Some(exchange)),
            None => store.add_exchange(*id, exchange),
        }
    }
}

/// Files stream messages under one captured exchange.
struct MessageSink {
    store: Arc<CaptureStore>,
    id: u64,
    index: usize,
}

impl MessageSink {
    fn push(&self, message: crate::capture::stream::StreamMessage) {
        self.store.push_message(self.id, self.index, message);
    }
}

/// Relays an upgraded WebSocket connection both ways unchanged, like
/// [`passthrough`], keeping its messages under `sink` as they pass (view
/// only, see [`crate::capture::websocket`]).
async fn relay_websocket<C, O>(
    client: Conn<C>,
    origin: Conn<O>,
    sink: MessageSink,
    deflate: Option<Deflate>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let (client, client_buffered) = client.into_parts();
    let (origin, origin_buffered) = origin.into_parts();
    let (mut client_read, mut client_write) =
        tokio::io::split(Prefixed::new(client, client_buffered));
    let (mut origin_read, mut origin_write) =
        tokio::io::split(Prefixed::new(origin, origin_buffered));
    let up = relay_messages(
        &mut client_read,
        &mut origin_write,
        WsParser::new(Direction::Up, deflate),
        &sink,
    );
    let down = relay_messages(
        &mut origin_read,
        &mut client_write,
        WsParser::new(Direction::Down, deflate),
        &sink,
    );
    // The first error ends both ways, as `copy_bidirectional` does.
    tokio::try_join!(up, down).map(|_| ())
}

/// One way of [`relay_websocket`]: bytes go on as read, then the parser
/// sees them; the end of `read` shuts `write` down.
async fn relay_messages<R, W>(
    read: &mut R,
    write: &mut W,
    mut parser: WsParser,
    sink: &MessageSink,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = read.read(&mut buf).await?;
        if n == 0 {
            return write.shutdown().await;
        }
        write.write_all(&buf[..n]).await?;
        write.flush().await?;
        if !parser.failed() {
            for message in parser.feed(&buf[..n], crate::capture::unix_millis()) {
                sink.push(message);
            }
        }
    }
}

/// `config` offering `h2` before `http/1.1`.
fn with_h2(mut config: ClientConfig) -> ClientConfig {
    config.alpn_protocols = vec![http2::ALPN_H2.to_vec(), b"http/1.1".to_vec()];
    config
}

/// Whether `first` starts a TLS handshake record.
fn is_tls(first: &[u8]) -> bool {
    first.first() == Some(&0x16)
}

/// The `Host` of a plain HTTP/1.x request that starts in `first`, when its
/// method is one the relay serves and its target is a path. An absolute
/// target (`GET http://... HTTP/1.1`, to a forward proxy) or `OPTIONS *`
/// is not one an origin is asked for, so such a connection is left alone.
fn plain_http_host(first: &[u8]) -> Option<String> {
    let method = PLAIN_HTTP_METHODS
        .iter()
        .find(|method| first.starts_with(method.as_bytes()))?;
    if first.get(method.len()) != Some(&b'/') {
        return None;
    }
    crate::sniff::http_host(first)
}

/// `host`, with `:port` when it is not the scheme's default.
fn authority(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Relays raw bytes both ways once rewriting stops, starting with whatever
/// each side had buffered.
async fn passthrough<C, O>(client: Conn<C>, origin: Conn<O>) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let (client, client_buffered) = client.into_parts();
    let (origin, origin_buffered) = origin.into_parts();
    let mut client = Prefixed::new(client, client_buffered);
    let mut origin = Prefixed::new(origin, origin_buffered);
    tokio::io::copy_bidirectional(&mut client, &mut origin)
        .await
        .map(|_| ())
}

fn split_request_line(line: &str) -> io::Result<(String, String, String)> {
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(path), Some(version), None)
            if !method.is_empty() && path.starts_with('/') && version.starts_with("HTTP/1.") =>
        {
            Ok((method.to_string(), path.to_string(), version.to_string()))
        }
        _ => Err(invalid("unsupported request line")),
    }
}

fn response_status(line: &str) -> io::Result<u16> {
    let mut parts = line.splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (Some(version), Some(status)) if version.starts_with("HTTP/1.") => status
            .parse::<u16>()
            .ok()
            .filter(|status| (100..1000).contains(status))
            .ok_or_else(|| invalid("invalid status code")),
        _ => Err(invalid("invalid status line")),
    }
}

fn response_head(
    status: u16,
    headers: &[MetadataEntry],
    location: Option<&str>,
    body_len: usize,
    close: bool,
) -> Head {
    let mut headers = from_metadata(headers);
    remove(&mut headers, "Transfer-Encoding");
    remove(&mut headers, "Content-Length");
    remove(&mut headers, "Connection");
    if let Some(location) = location {
        remove(&mut headers, "Location");
        headers.push(("Location".to_string(), location.to_string()));
    }
    headers.push(("Content-Length".to_string(), body_len.to_string()));
    if close {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    Head {
        start_line: format!("HTTP/1.1 {status} {}", reason(status)),
        headers,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

/// Bytes an HTTP/1.1 exchange takes from the engine's body budget before
/// it reads a body framed by `framing` for rules: its announced length, or
/// the most a held body grows to when no length is announced.
fn body_reservation(framing: Framing) -> usize {
    match framing {
        Framing::Length(length) => length.min(MAX_BODY_BYTES),
        Framing::Chunked | Framing::UntilClose => MAX_BODY_BYTES,
    }
}

/// Bytes a response takes from the engine's body budget before rules read
/// its body. A response that carries no body (`HEAD`, `204`, `304`) takes
/// nothing, even when it names a `Content-Encoding`; a coded body may
/// decode to up to [`MAX_BODY_BYTES`], so it takes that much; any other
/// body takes what [`body_reservation`] gives for its framing.
fn response_body_reservation(no_body: bool, coded: bool, framing: Framing) -> usize {
    if no_body {
        0
    } else if coded {
        MAX_BODY_BYTES
    } else {
        body_reservation(framing)
    }
}

/// A response body a rule reads, decoded when the origin sent it with a
/// `Content-Encoding` although the request asked for `identity`, so rules
/// and scripts see the text; the header goes and the body is sent on
/// decoded (the caller sets its length). A body that does not decode whole
/// within [`MAX_BODY_BYTES`] and the extension's window limit is left as it
/// came, with its header.
fn decoded_for_rules(headers: &mut Vec<(String, String)>, body: Vec<u8>) -> Vec<u8> {
    use crate::capture::decode::{codings, decode_body, DecodeLimits};

    let Some(coding) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.clone())
        .filter(|value| !codings(value).is_empty())
    else {
        return body;
    };
    let limits = DecodeLimits {
        output: MAX_BODY_BYTES,
        ..DecodeLimits::EXTENSION
    };
    match decode_body(&body, &coding, true, limits) {
        Ok(decoded) if !decoded.truncated => {
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-encoding"));
            decoded.data
        }
        _ => body,
    }
}

fn to_metadata(headers: &[(String, String)]) -> Vec<MetadataEntry> {
    headers
        .iter()
        .map(|(key, value)| MetadataEntry {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn from_metadata(headers: &[MetadataEntry]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

fn remove(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
}

/// Headers that frame and encode a body.
const BODY_FRAMING_HEADERS: [&str; 3] = ["Content-Length", "Transfer-Encoding", "Content-Encoding"];

/// A streamed body goes on exactly as `original` framed and encoded it, so
/// those headers stay the original's whatever a rule or a script without
/// `requires-body` did to the head (a script's `$done({headers})` replaces
/// all of them).
fn keep_streamed_body_headers(headers: &mut Vec<(String, String)>, original: &[(String, String)]) {
    for name in BODY_FRAMING_HEADERS {
        remove(headers, name);
        headers.extend(
            original
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .cloned(),
        );
    }
}

#[cfg(feature = "scripts")]
fn with_scripts(
    hook: NativeHttpMitmPluginHook,
    config: &MitmConfig,
    outbound: &Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    tls: &Arc<ClientConfig>,
) -> Result<
    (
        NativeHttpMitmPluginHook,
        Option<NativeQuickJsScriptExecutor>,
    ),
    &'static str,
> {
    let executor = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets: config.script_assets.clone(),
        persistent_store_path: config.script_store_path.clone(),
        max_timeout_ms: SCRIPT_MAX_TIMEOUT_MS,
        max_body_bytes: MAX_BODY_BYTES,
        memory_limit_bytes: SCRIPT_MEMORY_LIMIT_BYTES,
    })
    .map_err(|_| "mitm scripts are unavailable")?
    .with_memory_budget(SCRIPT_MEMORY_BUDGET_BYTES)
    .with_http_client(Arc::new(http_client::TunnelScriptHttpClient::new(
        outbound.clone(),
        tls.clone(),
    )));
    Ok((
        hook.with_quickjs_script_executor(executor.clone()),
        Some(executor),
    ))
}

#[cfg(not(feature = "scripts"))]
fn with_scripts(
    _hook: NativeHttpMitmPluginHook,
    _config: &MitmConfig,
    _outbound: &Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    _tls: &Arc<ClientConfig>,
) -> Result<(NativeHttpMitmPluginHook, Option<()>), &'static str> {
    Err("mitm scripts are not supported by this build")
}

/// PKCS#8 for a P-256 key given as ANSI X9.63 `04 || X || Y || D`, in the
/// exact layout `ring` produces and accepts.
pub fn p256_pkcs8_from_x963(key: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 97 || key[0] != 0x04 {
        return None;
    }
    const PREFIX: [u8; 36] = [
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    const PUBLIC_KEY: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];
    let mut der = Vec::with_capacity(138);
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(&key[65..97]);
    der.extend_from_slice(&PUBLIC_KEY);
    der.extend_from_slice(&key[..65]);
    Some(der)
}

/// Reads `prefix` before the wrapped stream; writes go straight through.
struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let n = (this.prefix.len() - this.offset).min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            if this.offset == this.prefix.len() {
                this.prefix = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// mitm-scripts-07: a full cache drops its older half, never the hosts
    /// in use.
    #[test]
    fn hostname_decisions_in_use_survive_a_full_cache() {
        let mut cache = DecisionCache::default();
        cache.insert("busy.example.test".to_string(), true);
        for index in 0..DECISION_CACHE_ENTRIES * 4 {
            cache.insert(format!("host-{index}.example.test"), false);
            if index % 64 == 0 {
                assert_eq!(cache.get("busy.example.test"), Some(true), "{index}");
            }
            assert!(cache.len() <= DECISION_CACHE_ENTRIES);
        }
        assert_eq!(cache.get("busy.example.test"), Some(true));
        assert_eq!(
            cache.get("host-0.example.test"),
            None,
            "an unused host left"
        );
        let last = format!("host-{}.example.test", DECISION_CACHE_ENTRIES * 4 - 1);
        assert_eq!(cache.get(&last), Some(false));
    }

    /// A response with no body (HEAD, 204, 304) takes nothing from the
    /// engine's body budget, even when it names a Content-Encoding, so it
    /// never goes busy for bytes it does not carry.
    #[test]
    fn bodiless_responses_reserve_no_body_budget() {
        for framing in [Framing::Length(0), Framing::Chunked, Framing::UntilClose] {
            assert_eq!(response_body_reservation(true, true, framing), 0);
            assert_eq!(response_body_reservation(true, false, framing), 0);
        }
        assert_eq!(
            response_body_reservation(false, true, Framing::Length(10)),
            MAX_BODY_BYTES
        );
        assert_eq!(
            response_body_reservation(false, false, Framing::Length(10)),
            10
        );
        assert_eq!(
            response_body_reservation(false, false, Framing::Length(MAX_BODY_BYTES * 2)),
            MAX_BODY_BYTES
        );
        assert_eq!(
            response_body_reservation(false, false, Framing::Chunked),
            MAX_BODY_BYTES
        );
        let budget = http2::BodyBudget::new(0);
        let mut held = http2::Held::new(&budget);
        assert!(held.grow(response_body_reservation(true, true, Framing::Length(0))));
    }
}
