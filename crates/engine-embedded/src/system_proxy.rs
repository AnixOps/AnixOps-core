//! The packet tunnel's HTTP/SOCKS5 proxy on `127.0.0.1`, for the system
//! proxy setting.
//!
//! On iOS and macOS the tunnel provider can also register an HTTP proxy with
//! the system (`NEProxySettings`). Apps that honor it, which is most traffic
//! through the system's URL loading, then send their connections here
//! instead of into the tunnel interface: they skip the userspace TCP/IP
//! stack, routing sees the requested name (`CONNECT host:443`) without
//! DNS or sniffing, and a plain HTTP request's head reaches `USER-AGENT` and
//! `URL-REGEX` rules. Traffic that ignores the proxy still takes the tunnel.
//! On macOS the provider can also register the proxy alone, with no routes
//! into the tunnel (the system proxy mode).
//!
//! The listener goes through the same [`Dispatcher`] as the tunnel's flows,
//! so routing, the connection list, capture and HTTPS decryption see its
//! connections the same way. It binds `127.0.0.1` only and asks for no
//! credentials: what can reach it could equally send the same connection
//! through the tunnel. On macOS each connection's local process is looked up
//! when the config has `PROCESS-NAME` rules ([`crate::process`]); iOS gives
//! no names.
//!
//! It may start before the tunnel does, so the provider can learn the port
//! and register it with the interface settings it applies before the tunnel
//! reads packets; stopping or dropping the runtime stops it. A whole-device
//! WireGuard tunnel has no dispatcher and refuses it.
//!
//! Control requests (answered by the packet tunnel runtime, ahead of
//! [`crate::control`]):
//!
//! | `cmd` | Request fields | Answer |
//! | --- | --- | --- |
//! | `system_proxy` | | [`SystemProxyStatus`] |
//! | `start_system_proxy` | optional `port` (default [`DEFAULT_PORT`]; when it is taken another free port is used, `0` always picks one) | [`SystemProxyStatus`] with the port in use; a running listener is restarted |
//! | `stop_system_proxy` | | [`SystemProxyStatus`] |

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use inbound_mixed::{ClientConnector, ClientInterceptor, MixedSettings, MixedStats, PeerFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::connections::Dispatcher;
use crate::control::MAX_REQUEST_LEN;
use crate::local_proxy::ProcessRouting;
use crate::{RuntimeError, RuntimeErrorCode};

/// The port asked for when the request names none.
pub const DEFAULT_PORT: u16 = 8890;

/// What a listener is started with.
#[derive(Clone, Copy, Debug)]
pub struct SystemProxyOptions {
    /// Preferred port on `127.0.0.1`; `0` picks a free one.
    pub port: u16,
    /// Client connections served at once.
    pub max_connections: usize,
}

/// A running listener. Stops when dropped.
pub struct SystemProxy {
    port: u16,
    https_decryption: bool,
    stats: Arc<MixedStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SystemProxy {
    /// Starts listening on `127.0.0.1` for `dispatcher`'s flows;
    /// `interceptor` decrypts HTTPS like the tunnel does.
    pub fn start(
        dispatcher: Arc<Dispatcher>,
        interceptor: Option<Arc<dyn ClientInterceptor>>,
        options: SystemProxyOptions,
    ) -> Result<Self, RuntimeError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| resource("system proxy runtime could not start"))?;
        let listener = {
            let _guard = runtime.enter();
            let std_listener = bind(options.port)?;
            std_listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(std_listener))
                .map_err(|_| resource("system proxy listener could not start"))?
        };
        let port = listener
            .local_addr()
            .map_err(|_| resource("system proxy listener could not start"))?
            .port();
        let https_decryption = interceptor.is_some();
        let settings = MixedSettings {
            max_connections: options.max_connections.max(1),
            // Bound to loopback, so only this device's apps reach it.
            peers: PeerFilter::Any,
            ..MixedSettings::default()
        };
        let connector = Arc::new(ProcessRouting(dispatcher)) as Arc<dyn ClientConnector>;
        let stats = Arc::new(MixedStats::default());
        let thread_stats = stats.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("networkcore-system-proxy".into())
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
            .map_err(|_| resource("system proxy thread could not start"))?;
        Ok(Self {
            port,
            https_decryption,
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

    pub fn status(&self) -> SystemProxyStatus {
        SystemProxyStatus {
            running: self.is_running(),
            host: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(self.port),
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

impl Drop for SystemProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Binds `port` on `127.0.0.1`, or a free port when that one is taken.
fn bind(port: u16) -> Result<TcpListener, RuntimeError> {
    let at = |port: u16| TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    match at(port) {
        Ok(listener) => Ok(listener),
        Err(_) if port != 0 => at(0),
        Err(err) => Err(err),
    }
    .map_err(|_| resource("system proxy port could not be bound"))
}

/// The answer to every system proxy control request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SystemProxyStatus {
    pub running: bool,
    /// Always `127.0.0.1` while running.
    pub host: Option<String>,
    /// The port in use, which differs from the one asked for when that one
    /// was taken.
    pub port: Option<u16>,
    /// Whether HTTPS to the `mitm` host list is decrypted.
    pub https_decryption: bool,
    /// Client connections accepted, refused (over the connection limit) and
    /// open now.
    pub accepted: u64,
    pub rejected: u64,
    pub active: u64,
    /// Failed accepts the listener survived (a client that reset before
    /// it was accepted, or descriptors or memory running short).
    pub accept_errors: u64,
}

/// Where a runtime keeps its listener; stopping the runtime stops it.
#[derive(Default)]
pub struct SystemProxySlot(Mutex<Option<SystemProxy>>);

impl SystemProxySlot {
    pub fn stop(&self) {
        let proxy = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(proxy);
    }

    pub fn status(&self) -> SystemProxyStatus {
        let slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.as_ref()
            .map_or_else(SystemProxyStatus::default, SystemProxy::status)
    }

    /// Answers `request` when it is a system proxy command; `None` for every
    /// other command. `start` starts a listener on the requested port.
    pub fn control(
        &self,
        request: &[u8],
        start: impl FnOnce(u16) -> Result<SystemProxy, RuntimeError>,
    ) -> Option<Result<Vec<u8>, RuntimeError>> {
        if request.is_empty() || request.len() > MAX_REQUEST_LEN {
            return None;
        }
        let command: SystemProxyControl = serde_json::from_slice(request).ok()?;
        let status = match command {
            SystemProxyControl::Status => Ok(self.status()),
            SystemProxyControl::Stop => {
                self.stop();
                Ok(SystemProxyStatus::default())
            }
            SystemProxyControl::Start { port } => {
                let mut slot = self
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // Free the port before a restart binds it again.
                drop(slot.take());
                start(port).map(|proxy| {
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
                    "system proxy status could not be encoded",
                )
            })
        }))
    }
}

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum SystemProxyControl {
    #[serde(rename = "system_proxy")]
    Status,
    #[serde(rename = "start_system_proxy")]
    Start {
        #[serde(default = "default_port")]
        port: u16,
    },
    #[serde(rename = "stop_system_proxy")]
    Stop,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_commands_are_left_alone() {
        let slot = SystemProxySlot::default();
        assert!(slot
            .control(br#"{"cmd":"replay_proxy"}"#, |_| unreachable!())
            .is_none());
        let stopped = slot
            .control(br#"{"cmd":"system_proxy"}"#, |_| unreachable!())
            .unwrap()
            .unwrap();
        let stopped: serde_json::Value = serde_json::from_slice(&stopped).unwrap();
        assert_eq!(stopped["running"], false);
        assert!(stopped["port"].is_null());
    }

    #[test]
    fn a_taken_port_falls_back_to_a_free_one() {
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let listener = bind(port).unwrap();
        let bound = listener.local_addr().unwrap();
        assert!(bound.ip().is_loopback());
        assert_ne!(bound.port(), port);
    }
}
