//! A proxy listener for the client's own requests, such as a debugger
//! replaying a captured request, so they go through the same routing,
//! capture and HTTPS decryption as the traffic of other apps.
//!
//! Platforms where the client's own sockets bypass the tunnel (Android's
//! `VpnService` excludes the app itself) point their HTTP client at this
//! listener instead. It is a SOCKS5/HTTP listener from `inbound-mixed` on
//! `127.0.0.1` only, on a port the system picks, and with credentials made
//! up on every start, so another app on the device cannot borrow it.
//! Connections carry the process name [`PROCESS_NAME`].
//!
//! Control requests (answered by the desktop local proxy and the packet
//! tunnel runtime, ahead of [`crate::control`]):
//!
//! | `cmd` | Request fields | Answer |
//! | --- | --- | --- |
//! | `replay_proxy` | | [`ReplayProxyStatus`] |
//! | `start_replay_proxy` | optional `decrypt` (default `true`: HTTPS to the `mitm` host list is decrypted, so the client must trust the `mitm` root) | [`ReplayProxyStatus`] with `port`, `username` and `password`; a running listener is restarted with new ones |
//! | `stop_replay_proxy` | | [`ReplayProxyStatus`] |

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use inbound_mixed::{
    ClientAddrs, ClientConnector, ClientInterceptor, Credentials, MixedSettings, MixedStats,
    PeerFilter,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::connections::Dispatcher;
use crate::control::MAX_REQUEST_LEN;
use crate::local_proxy::ClientProcess;
use crate::{RuntimeError, RuntimeErrorCode};

/// The process name of the listener's connections in the connection list,
/// capture and `PROCESS-NAME` rules.
pub const PROCESS_NAME: &str = "Replay";

/// A running listener. Stops when dropped.
pub struct ReplayProxy {
    port: u16,
    credentials: Credentials,
    https_decryption: bool,
    stats: Arc<MixedStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ReplayProxy {
    /// Starts listening on `127.0.0.1` for `dispatcher`'s flows;
    /// `interceptor` decrypts HTTPS like the other listeners do.
    pub fn start(
        dispatcher: Arc<Dispatcher>,
        interceptor: Option<Arc<dyn ClientInterceptor>>,
    ) -> Result<Self, RuntimeError> {
        let credentials = Credentials {
            username: format!("replay-{}", random_hex(4)?),
            password: random_hex(16)?,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| resource("replay proxy runtime could not start"))?;
        let listener = {
            let _guard = runtime.enter();
            let std_listener =
                std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .map_err(|_| resource("replay proxy port could not be bound"))?;
            std_listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(std_listener))
                .map_err(|_| resource("replay proxy listener could not start"))?
        };
        let port = listener
            .local_addr()
            .map_err(|_| resource("replay proxy listener could not start"))?
            .port();
        let https_decryption = interceptor.is_some();
        let settings = MixedSettings {
            max_connections: 64,
            credentials: Some(credentials.clone()),
            peers: PeerFilter::Any,
            ..MixedSettings::default()
        };
        let connector = Arc::new(ReplayClients(dispatcher)) as Arc<dyn ClientConnector>;
        let stats = Arc::new(MixedStats::default());
        let thread_stats = stats.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("networkcore-replay-proxy".into())
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
            .map_err(|_| resource("replay proxy thread could not start"))?;
        Ok(Self {
            port,
            credentials,
            https_decryption,
            stats,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    pub fn status(&self) -> ReplayProxyStatus {
        ReplayProxyStatus {
            running: self.is_running(),
            host: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(self.port),
            username: Some(self.credentials.username.clone()),
            password: Some(self.credentials.password.clone()),
            https_decryption: self.https_decryption,
            accepted: self.stats.accepted.load(Ordering::Relaxed),
            rejected: self.stats.rejected.load(Ordering::Relaxed),
            accept_errors: self.stats.accept_errors.load(Ordering::Relaxed),
            active: self.stats.active.load(Ordering::Relaxed),
        }
    }

    /// Stops listening and drops the listener's connections. Idempotent.
    pub fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ReplayProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The answer to every replay proxy control request. The credentials are
/// only for the client that asked; they change on every start.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReplayProxyStatus {
    pub running: bool,
    /// Always `127.0.0.1` while running.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Whether HTTPS to the `mitm` host list is decrypted.
    pub https_decryption: bool,
    /// Client connections accepted, refused (bad credentials or over the
    /// connection limit) and open now.
    pub accepted: u64,
    pub rejected: u64,
    pub active: u64,
    /// Failed accepts the listener survived (a client that reset before
    /// it was accepted, or descriptors or memory running short).
    pub accept_errors: u64,
}

/// Where a runtime keeps its listener; stopping the runtime stops it.
#[derive(Default)]
pub struct ReplayProxySlot(Mutex<Option<ReplayProxy>>);

impl ReplayProxySlot {
    pub fn stop(&self) {
        let proxy = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(proxy);
    }

    pub fn status(&self) -> ReplayProxyStatus {
        let slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.as_ref()
            .map_or_else(ReplayProxyStatus::default, ReplayProxy::status)
    }

    /// Answers `request` when it is a replay proxy command; `None` for every
    /// other command. `start` starts a listener, decrypting when asked.
    pub fn control(
        &self,
        request: &[u8],
        start: impl FnOnce(bool) -> Result<ReplayProxy, RuntimeError>,
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        if request.is_empty() || request.len() > MAX_REQUEST_LEN {
            return None;
        }
        let command: ReplayProxyControl = serde_json::from_slice(request).ok()?;
        let status = match command {
            ReplayProxyControl::Status => Ok(self.status()),
            ReplayProxyControl::Stop => {
                self.stop();
                Ok(ReplayProxyStatus::default())
            }
            ReplayProxyControl::Start { decrypt } => {
                let mut slot = self
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                drop(slot.take());
                start(decrypt).map(|proxy| {
                    let status = proxy.status();
                    *slot = Some(proxy);
                    status
                })
            }
        };
        Some(status.and_then(|status| {
            serde_json::to_vec(&status).map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::InternalError,
                    "replay proxy status could not be encoded",
                )
            })
        }))
    }
}

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum ReplayProxyControl {
    #[serde(rename = "replay_proxy")]
    Status,
    #[serde(rename = "start_replay_proxy")]
    Start {
        #[serde(default = "default_decrypt")]
        decrypt: bool,
    },
    #[serde(rename = "stop_replay_proxy")]
    Stop,
}

fn default_decrypt() -> bool {
    true
}

/// Routes the listener's connections under [`PROCESS_NAME`], passing the
/// head of a plain HTTP request to `USER-AGENT` and `URL-REGEX` rules.
struct ReplayClients(Arc<Dispatcher>);

impl ClientConnector for ReplayClients {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(ClientProcess::Named(PROCESS_NAME).connect(&self.0, client, target, &[]))
    }

    fn connect_client_with_first<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
        first: &'a [u8],
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(ClientProcess::Named(PROCESS_NAME).connect(&self.0, client, target, first))
    }
}

fn random_hex(len: usize) -> Result<String, RuntimeError> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| resource("replay proxy credentials could not be made"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_credentials_differ() {
        let first = random_hex(16).unwrap();
        let second = random_hex(16).unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn other_commands_are_left_alone() {
        let slot = ReplayProxySlot::default();
        assert!(slot
            .control(br#"{"cmd":"connections"}"#, |_| unreachable!())
            .is_none());
        let stopped = slot
            .control(br#"{"cmd":"replay_proxy"}"#, |_| unreachable!())
            .unwrap()
            .unwrap();
        let stopped: serde_json::Value = serde_json::from_slice(&stopped).unwrap();
        assert_eq!(stopped["running"], false);
        assert!(stopped["password"].is_null());
    }
}
