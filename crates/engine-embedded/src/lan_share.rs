//! Sharing the running engine with other devices on the local network, so a
//! phone can set this computer as its Wi-Fi proxy and have its traffic shown
//! (and, with a `mitm` section, decrypted) by the desktop client.
//!
//! A share is a second SOCKS5/HTTP listener from `inbound-mixed` on all IPv4
//! interfaces. It goes through the same [`Dispatcher`] as the computer's own
//! traffic, so routing, capture and the connection list see the phone's
//! connections too; each one carries the process name `LAN <phone address>`
//! ([`device_label`]) so the client can tell them apart. Only clients from
//! private and link-local addresses are answered
//! ([`PeerFilter::PrivateNetworks`]), optionally with proxy credentials.
//!
//! A device's flows that go DIRECT never reach this computer itself: its
//! loopback (`127.0.0.0/8`, `::1`, `localhost`), every interface address
//! (the one the device reached the share on included; only the share's own
//! port there stays open, for the setup page), link-local addresses and,
//! with `block_private_networks`, private networks are refused after routing
//! and name resolution, whatever the rules say; see [`crate::lan_guard`].
//! The computer's own programs (loopback clients of the share) are not
//! checked.
//!
//! The listener also serves a setup page ([`PAGE_HOST`]): opening
//! `http://<computer>:<port>/` on the phone (what the desktop client puts in
//! a QR code) shows the proxy address to enter and the downloads of the
//! root certificate of the `mitm` section: PEM, DER (`.crt`, for Android) and
//! an iOS configuration profile. Once the phone uses the proxy,
//! `http://cert.anixops/` answers the same page and says the proxy works.
//! Only the certificate is served, never its key.
//!
//! Control requests (answered by the desktop local proxy and the packet
//! tunnel runtime, ahead of [`crate::control`]):
//!
//! | `cmd` | Request fields | Answer |
//! | --- | --- | --- |
//! | `lan_share` | | [`LanShareStatus`] |
//! | `start_lan_share` | optional `port` (default [`DEFAULT_PORT`], `0` picks one), `username` and `password`, `block_private_networks` (default `false`) | [`LanShareStatus`]; a running share is restarted with the new settings |
//! | `stop_lan_share` | | [`LanShareStatus`] |

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use inbound_mixed::{
    ClientAddrs, ClientConnector, ClientInterceptor, ClientPages, Credentials, MixedSettings,
    MixedStats, PageRequest, PageResponse, PeerFilter,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::connections::{Dispatcher, FlowOrigin};
use crate::control::MAX_REQUEST_LEN;
use crate::lan_guard::LanPeer;
use crate::local_proxy::{Decrypting, LanDecrypting};
use crate::{RuntimeError, RuntimeErrorCode};

/// The made-up host name the setup page answers to through the proxy.
pub const PAGE_HOST: &str = "cert.anixops";

/// The port a share listens on when the request names none.
pub const DEFAULT_PORT: u16 = 8899;

const PEM_FILE: &str = "anixops-net-ca.pem";
const DER_FILE: &str = "anixops-net-ca.crt";
const PROFILE_FILE: &str = "anixops-net-ca.mobileconfig";

/// What a share is started with.
#[derive(Clone, Default)]
pub struct LanShareOptions {
    /// Port on all IPv4 interfaces; `0` picks a free one.
    pub port: u16,
    /// Proxy credentials the phone must send; the setup page needs none.
    pub credentials: Option<Credentials>,
    /// Also refuse DIRECT flows of other devices to private networks
    /// (RFC 1918, `100.64.0.0/10`, IPv6 ULA), not only to this computer;
    /// see [`crate::lan_guard`].
    pub block_private_networks: bool,
}

/// A running share. Stops when dropped.
pub struct LanShare {
    port: u16,
    https_decryption: bool,
    certificate: bool,
    credentials: bool,
    block_private_networks: bool,
    stats: Arc<MixedStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LanShare {
    /// Starts listening for `dispatcher`'s flows. `decrypting` decrypts
    /// HTTPS like on the computer's own listener; `certificate_der` is the
    /// root the setup page offers, normally that of the `mitm` section.
    pub fn start(
        dispatcher: Arc<Dispatcher>,
        decrypting: Option<Arc<Decrypting>>,
        certificate_der: Option<Vec<u8>>,
        options: LanShareOptions,
    ) -> Result<Self, RuntimeError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| resource("lan share runtime could not start"))?;
        let listener = {
            let _guard = runtime.enter();
            let std_listener = std::net::TcpListener::bind(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                options.port,
            )))
            .map_err(|_| resource("lan share port could not be bound"))?;
            std_listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(std_listener))
                .map_err(|_| resource("lan share listener could not start"))?
        };
        let port = listener
            .local_addr()
            .map_err(|_| resource("lan share listener could not start"))?
            .port();
        let block_private_networks = options.block_private_networks;
        // Decrypted connections of other devices are marked like the others.
        let interceptor = decrypting.map(|decrypting| {
            Arc::new(LanDecrypting {
                decrypting,
                block_private_networks,
            }) as Arc<dyn ClientInterceptor>
        });
        let https_decryption = interceptor.is_some();
        let certificate = certificate_der.map(|der| Arc::new(Certificate::new(der)));
        let pages = SetupPages {
            port,
            https_decryption,
            certificate: certificate.clone(),
        };
        let credentials = options.credentials.is_some();
        let settings = MixedSettings {
            credentials: options.credentials,
            peers: PeerFilter::PrivateNetworks,
            pages: Some(Arc::new(pages)),
            ..MixedSettings::default()
        };
        let connector = Arc::new(LanClients {
            dispatcher,
            block_private_networks,
        }) as Arc<dyn ClientConnector>;
        let stats = Arc::new(MixedStats::default());
        let thread_stats = stats.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("networkcore-lan-share".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let serve = inbound_mixed::serve_intercepted(
                        listener,
                        connector,
                        interceptor,
                        settings,
                        thread_stats,
                    );
                    tokio::select! {
                        _ = serve => {}
                        _ = shutdown_rx => {}
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .map_err(|_| resource("lan share thread could not start"))?;
        Ok(Self {
            port,
            https_decryption,
            certificate: certificate.is_some(),
            credentials,
            block_private_networks,
            stats,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    pub fn status(&self) -> LanShareStatus {
        let addresses = lan_addresses();
        LanShareStatus {
            running: self.is_running(),
            port: Some(self.port),
            url: addresses
                .first()
                .map(|address| format!("http://{address}:{}/", self.port)),
            addresses: addresses.iter().map(ToString::to_string).collect(),
            page_host: PAGE_HOST,
            https_decryption: self.https_decryption,
            certificate: self.certificate,
            credentials: self.credentials,
            block_private_networks: self.block_private_networks,
            accepted: self.stats.accepted.load(Ordering::Relaxed),
            rejected: self.stats.rejected.load(Ordering::Relaxed),
            accept_errors: self.stats.accept_errors.load(Ordering::Relaxed),
            active: self.stats.active.load(Ordering::Relaxed),
            pages: self.stats.pages.load(Ordering::Relaxed),
        }
    }

    /// Stops listening and drops the share's connections. Idempotent.
    pub fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LanShare {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The answer to every share control request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LanShareStatus {
    pub running: bool,
    pub port: Option<u16>,
    /// This computer's private IPv4 addresses, the likeliest first.
    pub addresses: Vec<String>,
    /// The setup page on the first address: what the QR code holds.
    pub url: Option<String>,
    pub page_host: &'static str,
    /// Whether HTTPS through the share is decrypted (a `mitm` section).
    pub https_decryption: bool,
    /// Whether the setup page offers a root certificate.
    pub certificate: bool,
    /// Whether the proxy asks for credentials.
    pub credentials: bool,
    /// Whether other devices' DIRECT flows to private networks are refused
    /// as well; flows to this computer itself always are.
    pub block_private_networks: bool,
    /// Client connections accepted, refused (not from a private address,
    /// or over the connection limit), open now, and setup pages served.
    pub accepted: u64,
    pub rejected: u64,
    pub active: u64,
    /// Failed accepts the listener survived (a client that reset before
    /// it was accepted, or descriptors or memory running short).
    pub accept_errors: u64,
    pub pages: u64,
}

impl LanShareStatus {
    fn stopped() -> Self {
        Self {
            page_host: PAGE_HOST,
            ..Self::default()
        }
    }
}

/// Where a runtime keeps its share; stopping the runtime stops it.
#[derive(Default)]
pub struct LanShareSlot(Mutex<Option<LanShare>>);

impl LanShareSlot {
    pub fn stop(&self) {
        let share = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(share);
    }

    pub fn status(&self) -> LanShareStatus {
        let slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.as_ref()
            .map_or_else(LanShareStatus::stopped, LanShare::status)
    }

    /// Answers `request` when it is a share command; `None` for every other
    /// command. `start` starts a share with the requested options.
    pub fn control(
        &self,
        request: &[u8],
        start: impl FnOnce(LanShareOptions) -> Result<LanShare, RuntimeError>,
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        if request.is_empty() || request.len() > MAX_REQUEST_LEN {
            return None;
        }
        let command: LanShareControl = serde_json::from_slice(request).ok()?;
        let status = match command {
            LanShareControl::Status => Ok(self.status()),
            LanShareControl::Stop => {
                self.stop();
                Ok(LanShareStatus::stopped())
            }
            LanShareControl::Start {
                port,
                username,
                password,
                block_private_networks,
            } => {
                let username = username.filter(|username| !username.is_empty());
                let password = password.filter(|password| !password.is_empty());
                let credentials = match (username, password) {
                    (Some(username), Some(password)) => Some(Credentials { username, password }),
                    (None, None) => None,
                    _ => {
                        return Some(Err(RuntimeError::new(
                            RuntimeErrorCode::InvalidArgument,
                            "lan share needs both a username and a password, or neither",
                        )))
                    }
                };
                let mut slot = self
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // Free the port before a restart binds it again.
                drop(slot.take());
                start(LanShareOptions {
                    port,
                    credentials,
                    block_private_networks,
                })
                .map(|share| {
                    let status = share.status();
                    *slot = Some(share);
                    status
                })
            }
        };
        Some(status.and_then(|status| {
            serde_json::to_vec(&status).map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::InternalError,
                    "lan share status could not be encoded",
                )
            })
        }))
    }
}

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum LanShareControl {
    #[serde(rename = "lan_share")]
    Status,
    #[serde(rename = "start_lan_share")]
    Start {
        #[serde(default = "default_port")]
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        block_private_networks: bool,
    },
    #[serde(rename = "stop_lan_share")]
    Stop,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// The process name a phone's connections carry in the connection list
/// and for `PROCESS-NAME` rules.
pub fn device_label(peer: IpAddr) -> String {
    format!("LAN {}", peer.to_canonical())
}

/// How the flows of `client` are checked: another device is a [`LanPeer`];
/// this computer's own programs (a loopback client) are not checked.
pub(crate) fn lan_peer(client: ClientAddrs, block_private_networks: bool) -> Option<LanPeer> {
    if client.peer.ip().to_canonical().is_loopback() {
        return None;
    }
    Some(LanPeer {
        via: client.local.ip().to_canonical(),
        share_port: client.local.port(),
        block_private_networks,
    })
}

/// Routes a phone's connections, named by the phone's address and kept away
/// from this computer itself (see [`crate::lan_guard`]).
struct LanClients {
    dispatcher: Arc<Dispatcher>,
    block_private_networks: bool,
}

impl ClientConnector for LanClients {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let label = device_label(client.peer.ip());
            let origin = FlowOrigin {
                process: Some(&label),
                source: crate::local_proxy::client_source(client),
                lan_peer: lan_peer(client, self.block_private_networks),
            };
            self.dispatcher
                .connect_origin_flow(target, None, origin, None)
                .await
        })
    }

    // No `open_client_udp`: the share does not answer UDP ASSOCIATE
    // (`MixedSettings::udp` stays off). Answering it needs the same check
    // on the UDP path of the dispatcher first.
}

/// The root certificate in the forms phones install.
struct Certificate {
    der: Vec<u8>,
    pem: String,
    profile: Vec<u8>,
    /// SHA-256 of the DER, upper-case hex pairs joined by `:`.
    fingerprint: String,
}

impl Certificate {
    fn new(der: Vec<u8>) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, &der);
        let digest = digest.as_ref();
        let fingerprint = digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let base64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = pem(&base64);
        let profile = configuration_profile(&base64, digest).into_bytes();
        Self {
            der,
            pem,
            profile,
            fingerprint,
        }
    }
}

fn pem(base64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// A name-based UUID from 16 bytes of `digest`.
fn uuid(digest: &[u8], salt: u8) -> String {
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = digest[index] ^ salt;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// An unsigned iOS configuration profile with one root certificate payload.
/// Its identifiers follow the certificate, so installing it again replaces
/// the earlier copy.
fn configuration_profile(base64: &str, digest: &[u8]) -> String {
    let short: String = digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let certificate_uuid = uuid(digest, 0x00);
    let profile_uuid = uuid(digest, 0x5a);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>{DER_FILE}</string>
			<key>PayloadContent</key>
			<data>{base64}</data>
			<key>PayloadDescription</key>
			<string>Root certificate for HTTPS debugging with AnixOps Net</string>
			<key>PayloadDisplayName</key>
			<string>AnixOps Net HTTPS Decryption Root</string>
			<key>PayloadIdentifier</key>
			<string>net.anixops.networkcore.lan-share.ca.{short}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{certificate_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Installs the root certificate of AnixOps Net on this device so that it can decrypt HTTPS for debugging. Trust it under Settings, General, About, Certificate Trust Settings.</string>
	<key>PayloadDisplayName</key>
	<string>AnixOps Net 抓包根证书</string>
	<key>PayloadIdentifier</key>
	<string>net.anixops.networkcore.lan-share.{short}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{profile_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#
    )
}

/// The setup page and its downloads.
struct SetupPages {
    port: u16,
    https_decryption: bool,
    certificate: Option<Arc<Certificate>>,
}

/// Which steps the setup page shows first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Apple,
    Android,
    Other,
}

fn platform(user_agent: Option<&str>) -> Platform {
    let agent = user_agent.unwrap_or_default();
    if agent.contains("Android") {
        Platform::Android
    } else if agent.contains("iPhone") || agent.contains("iPad") || agent.contains("iPod") {
        Platform::Apple
    } else {
        Platform::Other
    }
}

impl ClientPages for SetupPages {
    fn host(&self) -> &str {
        PAGE_HOST
    }

    fn respond(&self, client: ClientAddrs, request: &PageRequest) -> PageResponse {
        if !request.method.eq_ignore_ascii_case("GET")
            && !request.method.eq_ignore_ascii_case("HEAD")
        {
            return PageResponse {
                status: 405,
                content_type: "text/plain; charset=utf-8".to_string(),
                body: b"method not allowed\n".to_vec(),
                file_name: None,
            };
        }
        let path = request.path.split(['?', '#']).next().unwrap_or("/");
        let download = |content_type: &str, body: &[u8], file_name: &str| PageResponse {
            file_name: Some(file_name.to_string()),
            ..PageResponse::ok(content_type, body.to_vec())
        };
        match (path, self.certificate.as_deref()) {
            ("/" | "/index.html", _) => PageResponse::ok(
                "text/html; charset=utf-8",
                self.page(client, request).into_bytes(),
            ),
            ("/status.json", _) => PageResponse::ok(
                "application/json",
                serde_json::json!({
                    "proxied": request.proxied,
                    "https_decryption": self.https_decryption,
                    "certificate": self.certificate.is_some(),
                })
                .to_string()
                .into_bytes(),
            ),
            ("/ca.pem", Some(certificate)) => download(
                "application/x-pem-file",
                certificate.pem.as_bytes(),
                PEM_FILE,
            ),
            ("/ca.crt" | "/ca.cer", Some(certificate)) => {
                download("application/x-x509-ca-cert", &certificate.der, DER_FILE)
            }
            ("/ca.mobileconfig", Some(certificate)) => download(
                "application/x-apple-aspen-config",
                &certificate.profile,
                PROFILE_FILE,
            ),
            _ => PageResponse::not_found(),
        }
    }
}

impl SetupPages {
    fn page(&self, client: ClientAddrs, request: &PageRequest) -> String {
        // The address the phone reached this listener on is the one to enter.
        let server = client.local.ip().to_canonical();
        let port = self.port;
        let status = if request.proxied {
            r#"<p class="ok">✅ 代理已生效：这个页面经过电脑上的 AnixOps Net 打开。<br><span lang="en">The proxy works: this page came through AnixOps Net on the computer.</span></p>"#.to_string()
        } else {
            format!(
                r#"<p class="todo">还没有经过代理。按下面的步骤设置后，用浏览器打开 <code>http://{PAGE_HOST}</code> 检查。<br><span lang="en">Not through the proxy yet. After the steps below, open <code>http://{PAGE_HOST}</code> to check.</span></p>"#
            )
        };
        let certificate = match (&self.certificate, self.https_decryption) {
            (Some(certificate), true) => format!(
                r#"<p>电脑已开启 HTTPS 解密。要看手机的 HTTPS 内容，先在手机上安装并信任下面的根证书。<span lang="en">HTTPS decryption is on. Install and trust this root certificate to see the phone's HTTPS traffic.</span></p>
<p class="buttons"><a class="button" href="/ca.mobileconfig">iPhone / iPad 描述文件</a> <a class="button" href="/ca.crt">Android 证书 (.crt)</a> <a class="button secondary" href="/ca.pem">PEM</a></p>
<p class="small">SHA-256 指纹（与电脑上显示的一致才安装）<span lang="en">SHA-256 fingerprint (install only if it matches the computer)</span>:<br><code class="fingerprint">{}</code></p>"#,
                certificate.fingerprint
            ),
            (Some(_), false) | (None, _) => r#"<p>电脑没有开启 HTTPS 解密，只能看到连接和 HTTP 内容。在电脑上打开 HTTPS 解密后刷新本页即可下载根证书。<span lang="en">HTTPS decryption is off on the computer: only connections and plain HTTP are shown. Turn it on there and reload this page to get the root certificate.</span></p>"#.to_string(),
        };
        let apple = format!(
            r#"<section><h2>iPhone / iPad</h2><ol>
<li>设置 → 无线局域网 → 当前 Wi-Fi 右侧的 ⓘ → 配置代理 → 手动：服务器 <code>{server}</code>，端口 <code>{port}</code>。<span lang="en">Settings → Wi-Fi → ⓘ → Configure Proxy → Manual: server <code>{server}</code>, port <code>{port}</code>.</span></li>
<li>下载上面的描述文件，到 设置 → 通用 → VPN 与设备管理 安装。<span lang="en">Download the profile above and install it under Settings → General → VPN &amp; Device Management.</span></li>
<li>设置 → 通用 → 关于本机 → 证书信任设置，打开 “AnixOps Net HTTPS Decryption Root”。<span lang="en">Settings → General → About → Certificate Trust Settings: turn on full trust for the root.</span></li>
</ol></section>"#
        );
        let android = format!(
            r#"<section><h2>Android</h2><ol>
<li>设置 → WLAN → 长按当前网络 → 修改网络 → 高级 → 代理：手动，主机名 <code>{server}</code>，端口 <code>{port}</code>。<span lang="en">Settings → Wi-Fi → current network → Edit → Advanced → Proxy: Manual, host <code>{server}</code>, port <code>{port}</code>.</span></li>
<li>下载上面的 .crt，到 设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书 安装。<span lang="en">Download the .crt and install it under Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate.</span></li>
<li>Android 7 起，App 默认只信任系统证书；调试自己的 App 时在 network_security_config 里允许用户证书。<span lang="en">Since Android 7 apps trust only system roots by default; allow user roots in your own app's network_security_config.</span></li>
</ol></section>"#
        );
        let steps = match platform(request.user_agent.as_deref()) {
            Platform::Android => format!("{android}{apple}"),
            Platform::Apple | Platform::Other => format!("{apple}{android}"),
        };
        format!(
            r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AnixOps Net 抓包设置</title>
<style>
:root {{ color-scheme: light dark; --accent: #2563eb; --ok: #15803d; --muted: #6b7280; }}
body {{ font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Noto Sans CJK SC", sans-serif; margin: 0 auto; max-width: 640px; padding: 20px 16px 40px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
h2 {{ font-size: 18px; margin: 24px 0 8px; }}
code {{ font: 14px ui-monospace, SFMono-Regular, Menlo, monospace; background: rgba(127,127,127,.15); padding: 1px 5px; border-radius: 4px; }}
.fingerprint {{ word-break: break-all; display: inline-block; margin-top: 4px; }}
.proxy {{ font-size: 20px; margin: 12px 0; }}
.ok {{ color: var(--ok); }}
.todo {{ color: var(--muted); }}
.small {{ font-size: 13px; color: var(--muted); }}
.buttons {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.button {{ background: var(--accent); color: #fff; border-radius: 8px; padding: 8px 14px; text-decoration: none; }}
.button.secondary {{ background: rgba(127,127,127,.25); color: inherit; }}
span[lang=en] {{ display: block; font-size: 13px; color: var(--muted); }}
li {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<h1>AnixOps Net 抓包设置</h1>
<p class="small">Debug this device's traffic on the computer.</p>
<p class="proxy">代理 Proxy: <code>{server}:{port}</code></p>
{status}
{certificate}
{steps}
<p class="small">只抓你有权查看的流量。用完记得把 Wi-Fi 代理改回“关闭”。<span lang="en">Only capture traffic you are entitled to see. Turn the Wi-Fi proxy off when you are done.</span></p>
</body>
</html>
"#
        )
    }
}

/// This computer's private IPv4 addresses (RFC 1918), the likeliest one for
/// a phone on the same Wi-Fi first: the address of the default route, then
/// `192.168/16`, `10/8` and `172.16/12`. Tunnel and mesh-VPN addresses are
/// left out.
pub fn lan_addresses() -> Vec<Ipv4Addr> {
    let routed = routed_address();
    let mut addresses = Vec::new();
    for address in routed.into_iter().chain(interface_addresses()) {
        if address.is_private() && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses.sort_by_key(|address| {
        let [a, ..] = address.octets();
        let rank = match a {
            192 => 1,
            10 => 2,
            _ => 3,
        };
        (Some(*address) != routed, rank)
    });
    addresses
}

/// The source address the system would use for the internet. No packet is
/// sent: connecting a UDP socket only picks a route.
fn routed_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

/// IPv4 addresses of the interfaces that are up, loopback excluded. With a
/// packet tunnel the default route points into the tunnel, so the Wi-Fi
/// address is only found here.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn interface_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that stays valid until
    // freeifaddrs, which is called once below; entries are only read.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            let flags: u32 = entry.ifa_flags;
            let up = flags & (libc::IFF_UP as u32) != 0;
            let loopback = flags & (libc::IFF_LOOPBACK as u32) != 0;
            if up
                && !loopback
                && !entry.ifa_addr.is_null()
                && i32::from((*entry.ifa_addr).sa_family) == libc::AF_INET
            {
                let address = &*(entry.ifa_addr as *const libc::sockaddr_in);
                addresses.push(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn interface_addresses() -> Vec<Ipv4Addr> {
    Vec::new()
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> ClientAddrs {
        ClientAddrs {
            peer: "192.168.1.23:50000".parse().unwrap(),
            local: "192.168.1.5:8899".parse().unwrap(),
        }
    }

    fn get(path: &str, proxied: bool, user_agent: &str) -> PageRequest {
        PageRequest {
            method: "GET".into(),
            path: path.into(),
            host: None,
            user_agent: Some(user_agent.into()),
            proxied,
        }
    }

    fn pages(certificate: bool) -> SetupPages {
        SetupPages {
            port: 8899,
            https_decryption: certificate,
            certificate: certificate.then(|| Arc::new(Certificate::new(vec![0x30, 0x03, 1, 2, 3]))),
        }
    }

    #[test]
    fn page_names_the_address_the_phone_reached() {
        let page = pages(true).respond(addrs(), &get("/", false, "iPhone"));
        assert_eq!(page.status, 200);
        let html = String::from_utf8(page.body).unwrap();
        assert!(html.contains("192.168.1.5:8899"));
        assert!(html.contains("/ca.mobileconfig"));
        assert!(!html.contains("代理已生效"));
        let proxied = pages(true).respond(addrs(), &get("/?x=1", true, "Android"));
        let html = String::from_utf8(proxied.body).unwrap();
        assert!(html.contains("代理已生效"));
        // Android steps come first for an Android browser.
        assert!(html.find("<h2>Android").unwrap() < html.find("<h2>iPhone").unwrap());
    }

    #[test]
    fn certificate_downloads_need_a_root() {
        let with = pages(true);
        let pem = with.respond(addrs(), &get("/ca.pem", false, ""));
        assert_eq!(pem.status, 200);
        assert_eq!(pem.file_name.as_deref(), Some(PEM_FILE));
        let pem = String::from_utf8(pem.body).unwrap();
        assert_eq!(
            pem,
            "-----BEGIN CERTIFICATE-----\nMAMBAgM=\n-----END CERTIFICATE-----\n"
        );
        let der = with.respond(addrs(), &get("/ca.crt", false, ""));
        assert_eq!(der.body, vec![0x30, 0x03, 1, 2, 3]);
        let profile = with.respond(addrs(), &get("/ca.mobileconfig", false, ""));
        assert_eq!(profile.content_type, "application/x-apple-aspen-config");
        let profile = String::from_utf8(profile.body).unwrap();
        assert!(profile.contains("<data>MAMBAgM=</data>"));
        assert!(profile.contains("com.apple.security.root"));

        let without = pages(false);
        assert_eq!(
            without.respond(addrs(), &get("/ca.pem", false, "")).status,
            404
        );
        let html = String::from_utf8(without.respond(addrs(), &get("/", false, "")).body).unwrap();
        assert!(!html.contains("/ca.crt"));
    }

    #[test]
    fn other_methods_and_paths_are_refused() {
        let mut post = get("/", false, "");
        post.method = "POST".into();
        assert_eq!(pages(true).respond(addrs(), &post).status, 405);
        assert_eq!(
            pages(true)
                .respond(addrs(), &get("/../etc/passwd", false, ""))
                .status,
            404
        );
    }

    #[test]
    fn uuids_are_stable_and_well_formed() {
        let digest = [0xabu8; 32];
        let first = uuid(&digest, 0);
        assert_eq!(first, uuid(&digest, 0));
        assert_ne!(first, uuid(&digest, 0x5a));
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "5");
    }

    #[test]
    fn share_commands_are_told_apart_from_others() {
        let slot = LanShareSlot::default();
        assert!(slot
            .control(br#"{"cmd":"connections"}"#, |_| unreachable!())
            .is_none());
        let status = slot
            .control(br#"{"cmd":"lan_share"}"#, |_| unreachable!())
            .unwrap()
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["page_host"], PAGE_HOST);
        assert!(slot
            .control(
                br#"{"cmd":"start_lan_share","username":"u"}"#,
                |_| unreachable!()
            )
            .unwrap()
            .is_err());
    }

    #[test]
    fn device_labels_name_the_phone() {
        assert_eq!(
            device_label("::ffff:192.168.1.23".parse().unwrap()),
            "LAN 192.168.1.23"
        );
    }

    #[test]
    fn other_devices_are_lan_peers_and_this_computer_is_not() {
        let own = ClientAddrs {
            peer: "127.0.0.1:50000".parse().unwrap(),
            local: "127.0.0.1:8899".parse().unwrap(),
        };
        assert_eq!(lan_peer(own, true), None);
        let phone = ClientAddrs {
            peer: "[::ffff:192.168.1.23]:50000".parse().unwrap(),
            local: "[::ffff:192.168.1.5]:8899".parse().unwrap(),
        };
        assert_eq!(
            lan_peer(phone, true),
            Some(LanPeer {
                via: "192.168.1.5".parse().unwrap(),
                share_port: 8899,
                block_private_networks: true,
            })
        );
    }

    #[test]
    fn a_phone_cannot_reach_this_computers_loopback_services() {
        // A service that listens on loopback only, like a database or the
        // Docker API.
        let service = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = service.local_addr().unwrap().port();
        let clients = LanClients {
            dispatcher: Arc::new(Dispatcher::single(Arc::new(
                crate::direct::DirectOutbound::new(Arc::new(engine_outbound::TcpDialer)),
            ))),
            block_private_networks: false,
        };
        let phone = ClientAddrs {
            peer: "192.168.1.23:50000".parse().unwrap(),
            local: "192.0.2.5:8899".parse().unwrap(),
        };
        let mut targets = vec![
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
            TargetAddr::Ip(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))),
            TargetAddr::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))),
            TargetAddr::Domain("localhost".to_string(), port),
            TargetAddr::Domain("127.0.0.1".to_string(), port),
        ];
        // This computer's network addresses.
        targets.extend(
            lan_addresses()
                .into_iter()
                .map(|address| TargetAddr::Ip(SocketAddr::from((address, port)))),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for target in &targets {
                let refused = clients.connect_client(phone, target).await.err();
                assert_eq!(
                    refused.map(|error| error.kind()),
                    Some(io::ErrorKind::PermissionDenied),
                    "{target}"
                );
            }
            // Nor the address it reached the share on: a service there that
            // the host firewall keeps from the network stays out of reach.
            for address in lan_addresses() {
                let phone = ClientAddrs {
                    peer: "192.168.1.23:50000".parse().unwrap(),
                    local: SocketAddr::from((address, 8899)),
                };
                let target = TargetAddr::Ip(SocketAddr::from((address, port)));
                let refused = clients.connect_client(phone, &target).await.err();
                assert_eq!(
                    refused.map(|error| error.kind()),
                    Some(io::ErrorKind::PermissionDenied),
                    "{target}"
                );
            }
            // The computer's own programs on the share's port still can.
            let own = ClientAddrs {
                peer: "127.0.0.1:50000".parse().unwrap(),
                local: "127.0.0.1:8899".parse().unwrap(),
            };
            clients.connect_client(own, &targets[0]).await.unwrap();
        });
        let closed = clients.dispatcher.tracker().connections().closed;
        assert!(closed
            .iter()
            .filter(|connection| connection.process.as_deref() == Some("LAN 192.168.1.23"))
            .all(|connection| connection.error == Some(crate::lan_guard::REFUSED)));
    }

    #[test]
    fn lan_addresses_are_private() {
        for address in lan_addresses() {
            assert!(address.is_private(), "{address}");
        }
    }
}
