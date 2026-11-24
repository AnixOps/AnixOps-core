//! Loopback listeners and the accept loop's handle.

use super::*;

pub(crate) struct NativeBoundedRead<'a, R> {
    pub(crate) reader: &'a mut R,
    pub(crate) deadline: Instant,
}

impl<'a, R> NativeBoundedRead<'a, R> {
    pub(crate) fn new(reader: &'a mut R, timeout: Duration) -> Self {
        Self {
            reader,
            deadline: Instant::now() + timeout,
        }
    }
}

impl<R> Read for NativeBoundedRead<'_, R>
where
    R: Read,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "native bounded HTTP read timed out",
                ));
            }
            match self.reader.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackListenerHandle {
    pub listener_id: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub kind: ListenerKind,
    pub network: ListenerNetwork,
}

impl LoopbackListenerHandle {
    pub fn from_descriptor(listener: &ListenerDescriptor) -> DomainResult<Self> {
        if !listener.enabled {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE,
                "disabled listeners cannot own native runtime handles",
            ));
        }

        if listener.bind.host.trim().is_empty() || listener.bind.port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
                "native runtime listener bind host and port must be explicit",
            ));
        }

        if !is_loopback_host(&listener.bind.host) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
                "first native runtime listener handle must bind to loopback",
            ));
        }

        if listener.network != ListenerNetwork::Tcp
            || !listener_runtime_kind_supported(&listener.kind)
        {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE,
                "first native runtime listener handle only supports tcp loopback listeners",
            ));
        }

        Ok(Self {
            listener_id: listener.id.clone(),
            bind_host: listener.bind.host.clone(),
            bind_port: listener.bind.port,
            kind: listener.kind.clone(),
            network: listener.network,
        })
    }
}

#[derive(Debug)]
pub struct BoundLoopbackTcpListenerHandle {
    pub(crate) listener: TcpListener,
    pub(crate) contract: LoopbackListenerHandle,
    pub(crate) local_host: String,
    pub(crate) local_port: u16,
}

impl BoundLoopbackTcpListenerHandle {
    pub fn bind(contract: LoopbackListenerHandle) -> DomainResult<Self> {
        if contract.bind_host.trim().is_empty() || contract.bind_port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
                "native runtime listener bind host and port must be explicit",
            ));
        }

        if !is_loopback_host(&contract.bind_host) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
                "native loopback tcp listener bind requires a loopback address",
            ));
        }

        if contract.network != ListenerNetwork::Tcp
            || !listener_runtime_kind_supported(&contract.kind)
        {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE,
                "native loopback tcp listener only supports tcp loopback listeners",
            ));
        }

        let listener = TcpListener::bind((contract.bind_host.as_str(), contract.bind_port))
            .map_err(|_| {
                runtime_error(
                    ENGINE_NATIVE_START_BIND_FAILED_CODE,
                    "failed to bind native loopback tcp listener",
                )
            })?;
        let local_addr = listener.local_addr().map_err(|_| {
            runtime_error(
                ENGINE_NATIVE_START_BIND_FAILED_CODE,
                "failed to inspect native loopback tcp listener address",
            )
        })?;

        Ok(Self {
            listener,
            contract,
            local_host: local_addr.ip().to_string(),
            local_port: local_addr.port(),
        })
    }

    pub fn listener_id(&self) -> &str {
        &self.contract.listener_id
    }

    pub fn bind_host(&self) -> &str {
        &self.contract.bind_host
    }

    pub fn bind_port(&self) -> u16 {
        self.contract.bind_port
    }

    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn release(self) -> BoundLoopbackTcpListenerReleaseReport {
        let Self {
            listener,
            contract,
            local_host,
            local_port,
        } = self;
        drop(listener);

        BoundLoopbackTcpListenerReleaseReport {
            listener_id: contract.listener_id,
            bind_host: contract.bind_host,
            bind_port: contract.bind_port,
            local_host,
            local_port,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
                "native loopback tcp listener was released",
            )],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundLoopbackTcpListenerReleaseReport {
    pub listener_id: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeLoopbackTcpAcceptLoopHandle {
    pub(crate) listener_id: String,
    pub(crate) outbound_handler_id: String,
    pub(crate) local_host: String,
    pub(crate) local_port: u16,
    pub(crate) accepted_connections: Arc<AtomicUsize>,
    pub(crate) pre_protocol_closed_connections: Arc<AtomicUsize>,
    pub(crate) relayed_connections: Arc<AtomicUsize>,
    pub(crate) shutdown_tx: Option<mpsc::Sender<()>>,
    pub(crate) worker: Option<JoinHandle<NativeLoopbackTcpAcceptLoopShutdownReport>>,
}

impl NativeLoopbackTcpAcceptLoopHandle {
    pub fn start(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
    ) -> DomainResult<Self> {
        Self::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            listener,
            outbound_handler,
            None,
            None,
        )
    }

    pub fn start_with_http_mitm_hook(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    ) -> DomainResult<Self> {
        Self::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            listener,
            outbound_handler,
            http_mitm_hook,
            None,
        )
    }

    pub fn start_with_http_mitm_hook_and_tls_mitm_ca_material(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
        tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    ) -> DomainResult<Self> {
        let BoundLoopbackTcpListenerHandle {
            listener,
            contract,
            local_host,
            local_port,
        } = listener;

        listener.set_nonblocking(true).map_err(|_| {
            runtime_error(
                ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                "failed to configure native loopback tcp accept loop",
            )
        })?;

        let listener_id = contract.listener_id;
        let listener_kind = contract.kind;
        let outbound_handler_id = outbound_handler.node_id.clone();
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let accepted_connections_for_worker = Arc::clone(&accepted_connections);
        let pre_protocol_closed_connections = Arc::new(AtomicUsize::new(0));
        let pre_protocol_closed_connections_for_worker =
            Arc::clone(&pre_protocol_closed_connections);
        let relayed_connections = Arc::new(AtomicUsize::new(0));
        let relayed_connections_for_worker = Arc::clone(&relayed_connections);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let worker_listener_id = listener_id.clone();
        let worker_outbound_handler_id = outbound_handler_id.clone();
        let worker_local_host = local_host.clone();

        let worker = thread::spawn(move || {
            run_loopback_tcp_accept_loop(
                listener,
                shutdown_rx,
                accepted_connections_for_worker,
                pre_protocol_closed_connections_for_worker,
                relayed_connections_for_worker,
                NativeLoopbackTcpAcceptLoopIdentity {
                    listener_id: worker_listener_id,
                    listener_kind,
                    outbound_handler_id: worker_outbound_handler_id,
                    outbound_handler,
                    http_mitm_hook,
                    tls_mitm_ca_material,
                    local_host: worker_local_host,
                    local_port,
                },
            )
        });

        Ok(Self {
            listener_id,
            outbound_handler_id,
            local_host,
            local_port,
            accepted_connections,
            pre_protocol_closed_connections,
            relayed_connections,
            shutdown_tx: Some(shutdown_tx),
            worker: Some(worker),
        })
    }

    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }

    pub fn outbound_handler_id(&self) -> &str {
        &self.outbound_handler_id
    }

    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn accepted_connections(&self) -> usize {
        self.accepted_connections.load(Ordering::SeqCst)
    }

    pub fn pre_protocol_closed_connections(&self) -> usize {
        self.pre_protocol_closed_connections.load(Ordering::SeqCst)
    }

    pub fn relayed_connections(&self) -> usize {
        self.relayed_connections.load(Ordering::SeqCst)
    }

    pub fn shutdown(mut self) -> NativeLoopbackTcpAcceptLoopShutdownReport {
        self.shutdown_inner()
    }

    pub(crate) fn shutdown_inner(&mut self) -> NativeLoopbackTcpAcceptLoopShutdownReport {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(report) => report,
                Err(_) => NativeLoopbackTcpAcceptLoopShutdownReport {
                    listener_id: self.listener_id.clone(),
                    outbound_handler_id: self.outbound_handler_id.clone(),
                    local_host: self.local_host.clone(),
                    local_port: self.local_port,
                    accepted_connections: self.accepted_connections(),
                    pre_protocol_closed_connections: self.pre_protocol_closed_connections(),
                    relayed_connections: self.relayed_connections(),
                    diagnostics: vec![engine_diagnostic(
                        DiagnosticSeverity::Error,
                        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                        "native loopback tcp accept loop worker failed during shutdown",
                        SOURCE_ENGINE_NATIVE_RUNTIME,
                    )],
                },
            }
        } else {
            NativeLoopbackTcpAcceptLoopShutdownReport {
                listener_id: self.listener_id.clone(),
                outbound_handler_id: self.outbound_handler_id.clone(),
                local_host: self.local_host.clone(),
                local_port: self.local_port,
                accepted_connections: self.accepted_connections(),
                pre_protocol_closed_connections: self.pre_protocol_closed_connections(),
                relayed_connections: self.relayed_connections(),
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
                    "native loopback tcp accept loop was already stopped",
                )],
            }
        }
    }
}

impl Drop for NativeLoopbackTcpAcceptLoopHandle {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.shutdown_inner();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLoopbackTcpAcceptLoopShutdownReport {
    pub listener_id: String,
    pub outbound_handler_id: String,
    pub local_host: String,
    pub local_port: u16,
    pub accepted_connections: usize,
    pub pre_protocol_closed_connections: usize,
    pub relayed_connections: usize,
    pub diagnostics: Vec<Diagnostic>,
}
