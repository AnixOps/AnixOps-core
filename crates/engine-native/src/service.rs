//! The runtime handle and assembly, and the engine service's lifecycle.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOutboundHandlerHandle {
    pub node_id: String,
    pub protocol: Protocol,
    pub endpoint: Endpoint,
}

impl NativeOutboundHandlerHandle {
    pub fn from_node(node: &NodeDescriptor) -> DomainResult<Self> {
        if node.endpoint.host.trim().is_empty() || node.endpoint.port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE,
                "native runtime outbound endpoint host and port must be explicit",
            ));
        }

        if !outbound_runtime_protocol_supported(&node.protocol) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE,
                "first native runtime outbound handler only declares socks node handoff",
            ));
        }

        Ok(Self {
            node_id: node.id.clone(),
            protocol: node.protocol.clone(),
            endpoint: node.endpoint.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeAssemblyPlan {
    pub(crate) engine_id: String,
    pub(crate) listener: LoopbackListenerHandle,
    pub(crate) outbound_handler: NativeOutboundHandlerHandle,
}

impl NativeRuntimeAssemblyPlan {
    pub fn from_config(engine_config: &ProxyEngineConfig) -> DomainResult<Self> {
        ensure_native_engine_id(&engine_config.engine_id)?;
        ensure_native_config_has_no_errors(engine_config)?;

        let mut first_error = None;
        for listener_descriptor in enabled_listeners(&engine_config.config.listeners) {
            let listener = match LoopbackListenerHandle::from_descriptor(listener_descriptor) {
                Ok(listener) => listener,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let node = match select_runtime_node(engine_config, listener_descriptor) {
                Ok(node) => node,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let outbound_handler = match NativeOutboundHandlerHandle::from_node(node) {
                Ok(outbound_handler) => outbound_handler,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };

            return Ok(Self {
                engine_id: engine_config.engine_id.clone(),
                listener,
                outbound_handler,
            });
        }

        Err(first_error.unwrap_or_else(|| {
            runtime_error(
                ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
                "native runtime assembly plan requires a loopback tcp listener and socks outbound handler",
            )
        }))
    }

    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub fn listener(&self) -> &LoopbackListenerHandle {
        &self.listener
    }

    pub fn outbound_handler(&self) -> &NativeOutboundHandlerHandle {
        &self.outbound_handler
    }

    pub fn into_unbound_assembly(self) -> NativeRuntimeAssembly {
        NativeRuntimeAssembly::new(self.engine_id)
            .with_listener(self.listener)
            .with_outbound_handler(self.outbound_handler)
    }

    pub fn bind_loopback_listener(
        self,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        let Self {
            engine_id,
            listener,
            outbound_handler,
        } = self;
        let release_listener = listener.clone();

        match BoundLoopbackTcpListenerHandle::bind(listener) {
            Ok(bound_listener) => Ok(NativeRuntimeAssembly::new(engine_id)
                .with_bound_listener(bound_listener)
                .with_outbound_handler(outbound_handler)),
            Err(error) => Err(Box::new(
                NativeRuntimeAssembly::new(engine_id)
                    .with_listener(release_listener)
                    .with_outbound_handler(outbound_handler)
                    .fail(error.code.clone(), error.message.clone()),
            )),
        }
    }

    pub fn start_loopback_accept_loop(
        self,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        self.start_loopback_accept_loop_with_http_mitm_hook(None)
    }

    pub fn start_loopback_accept_loop_with_http_mitm_hook(
        self,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        self.start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
            http_mitm_hook,
            None,
        )
    }

    pub fn start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
        self,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
        tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        let Self {
            engine_id,
            listener,
            outbound_handler,
        } = self;
        let release_listener = listener.clone();
        let release_outbound_handler = outbound_handler.clone();

        let bound_listener = match BoundLoopbackTcpListenerHandle::bind(listener) {
            Ok(bound_listener) => bound_listener,
            Err(error) => {
                return Err(Box::new(
                    NativeRuntimeAssembly::new(engine_id)
                        .with_listener(release_listener)
                        .with_outbound_handler(outbound_handler)
                        .fail(error.code.clone(), error.message.clone()),
                ));
            }
        };

        match NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            bound_listener,
            outbound_handler,
            http_mitm_hook,
            tls_mitm_ca_material,
        ) {
            Ok(accept_loop) => {
                Ok(NativeRuntimeAssembly::new(engine_id).with_accept_loop(accept_loop))
            }
            Err(error) => Err(Box::new(
                NativeRuntimeAssembly::new(engine_id)
                    .with_listener(release_listener)
                    .with_outbound_handler(release_outbound_handler)
                    .fail(error.code.clone(), error.message.clone()),
            )),
        }
    }
}

#[derive(Debug)]
pub struct NativeRuntimeHandle {
    pub(crate) engine_id: String,
    pub(crate) listeners: Vec<LoopbackListenerHandle>,
    pub(crate) bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    pub(crate) accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    pub(crate) outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    pub(crate) events: Vec<ProxyEngineEvent>,
}

impl NativeRuntimeHandle {
    pub fn listeners(&self) -> &[LoopbackListenerHandle] {
        &self.listeners
    }

    pub fn bound_listeners(&self) -> &[BoundLoopbackTcpListenerHandle] {
        &self.bound_listeners
    }

    pub fn accept_loops(&self) -> &[NativeLoopbackTcpAcceptLoopHandle] {
        &self.accept_loops
    }

    pub fn outbound_handlers(&self) -> &[NativeOutboundHandlerHandle] {
        &self.outbound_handlers
    }

    pub fn events(&self) -> &[ProxyEngineEvent] {
        &self.events
    }

    pub fn foreground_handoff_status(&self) -> ProxyEngineStatus {
        let mut diagnostics = vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
            "native runtime handle is ready for foreground lifecycle handoff",
        )];
        if !self.accept_loops.is_empty() {
            diagnostics.push(runtime_info(
                ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
                "native loopback tcp accept loop is ready",
            ));
        }

        ProxyEngineStatus {
            engine_id: self.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics,
        }
    }

    pub fn release(self) -> NativeRuntimeReleaseReport {
        release_report(
            NativeRuntimeReleaseResources {
                engine_id: self.engine_id,
                listeners: self.listeners,
                bound_listeners: self.bound_listeners,
                accept_loops: self.accept_loops,
                outbound_handlers: self.outbound_handlers,
                events: self.events,
            },
            ProxyEngineEventKind::Stopped,
            Vec::new(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeReleaseReport {
    pub engine_id: String,
    pub listener_ids: Vec<String>,
    pub outbound_handler_ids: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub events: Vec<ProxyEngineEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeStartupFailure {
    pub error: DomainError,
    pub release: NativeRuntimeReleaseReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProxyEngineStartReadiness {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProxyEngineStartReadinessReport {
    pub readiness: NativeProxyEngineStartReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeRuntimeAssembly {
    pub(crate) engine_id: String,
    pub(crate) listeners: Vec<LoopbackListenerHandle>,
    pub(crate) bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    pub(crate) accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    pub(crate) outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    pub(crate) events: Vec<ProxyEngineEvent>,
}

impl NativeRuntimeAssembly {
    pub fn new(engine_id: impl Into<String>) -> Self {
        Self {
            engine_id: engine_id.into(),
            listeners: Vec::new(),
            bound_listeners: Vec::new(),
            accept_loops: Vec::new(),
            outbound_handlers: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn with_listener(mut self, listener: LoopbackListenerHandle) -> Self {
        self.listeners.push(listener);
        self
    }

    pub fn with_bound_listener(mut self, listener: BoundLoopbackTcpListenerHandle) -> Self {
        self.bound_listeners.push(listener);
        self
    }

    pub fn with_accept_loop(mut self, accept_loop: NativeLoopbackTcpAcceptLoopHandle) -> Self {
        self.accept_loops.push(accept_loop);
        self
    }

    pub fn with_outbound_handler(mut self, outbound_handler: NativeOutboundHandlerHandle) -> Self {
        self.outbound_handlers.push(outbound_handler);
        self
    }

    pub fn finish(mut self) -> DomainResult<NativeRuntimeHandle> {
        ensure_native_engine_id(&self.engine_id)?;

        let has_listener_resource = !self.listeners.is_empty()
            || !self.bound_listeners.is_empty()
            || !self.accept_loops.is_empty();
        let has_outbound_resource =
            !self.outbound_handlers.is_empty() || !self.accept_loops.is_empty();

        if !has_listener_resource || !has_outbound_resource {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
                "native runtime handle requires at least one listener and outbound handler",
            ));
        }

        let mut diagnostics = vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
            "native runtime handle is ready for foreground lifecycle handoff",
        )];
        if !self.accept_loops.is_empty() {
            diagnostics.push(runtime_info(
                ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
                "native loopback tcp accept loop is ready",
            ));
        }

        self.events.push(runtime_event(
            &self.engine_id,
            ProxyEngineEventKind::Started,
            diagnostics,
        ));

        Ok(NativeRuntimeHandle {
            engine_id: self.engine_id,
            listeners: self.listeners,
            bound_listeners: self.bound_listeners,
            accept_loops: self.accept_loops,
            outbound_handlers: self.outbound_handlers,
            events: self.events,
        })
    }

    pub fn fail(
        self,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> NativeRuntimeStartupFailure {
        let error = DomainError::new(code, message);
        let failure_diagnostic = engine_diagnostic(
            DiagnosticSeverity::Error,
            error.code.clone(),
            error.message.clone(),
            SOURCE_ENGINE_NATIVE_RUNTIME,
        );
        let release = release_report(
            NativeRuntimeReleaseResources {
                engine_id: self.engine_id,
                listeners: self.listeners,
                bound_listeners: self.bound_listeners,
                accept_loops: self.accept_loops,
                outbound_handlers: self.outbound_handlers,
                events: self.events,
            },
            ProxyEngineEventKind::Failed,
            vec![failure_diagnostic],
        );

        NativeRuntimeStartupFailure { error, release }
    }
}

#[derive(Debug)]
pub(crate) struct NativeManagedRuntime {
    pub(crate) handle: NativeRuntimeHandle,
    pub(crate) config: ProxyEngineConfig,
}

#[derive(Debug, Clone, Default)]
pub struct NativeProxyEngineService {
    pub(crate) runtime: Arc<Mutex<Option<NativeManagedRuntime>>>,
    pub(crate) lifecycle_events: Arc<Mutex<Vec<ProxyEngineEvent>>>,
    pub(crate) http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    pub(crate) tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
}

impl NativeProxyEngineService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_http_mitm_hook(mut self, hook: NativeHttpMitmPluginHook) -> Self {
        self.http_mitm_hook = Some(hook);
        self
    }

    pub fn with_tls_mitm_ca_material(mut self, material: NativeTlsMitmCaMaterial) -> Self {
        self.tls_mitm_ca_material = Some(material);
        self
    }

    pub fn http_mitm_hook_enabled(&self) -> bool {
        self.http_mitm_hook.is_some()
    }

    pub fn tls_mitm_ca_material_enabled(&self) -> bool {
        self.tls_mitm_ca_material.is_some()
    }

    pub fn http_mitm_script_executor_enabled(&self) -> bool {
        match self.http_mitm_hook.as_ref() {
            Some(hook) => hook.script_executor_enabled(),
            None => false,
        }
    }

    pub fn http_mitm_script_engine(&self) -> Option<&'static str> {
        self.http_mitm_hook
            .as_ref()
            .and_then(NativeHttpMitmPluginHook::script_engine)
    }

    pub fn http_mitm_script_sandbox(&self) -> Option<NativeNodeScriptSandbox> {
        self.http_mitm_hook
            .as_ref()
            .and_then(NativeHttpMitmPluginHook::script_sandbox)
    }

    pub(crate) fn runtime_state(
        &self,
    ) -> DomainResult<std::sync::MutexGuard<'_, Option<NativeManagedRuntime>>> {
        self.runtime.lock().map_err(|_| lifecycle_state_error())
    }

    pub(crate) fn lifecycle_event_state(
        &self,
    ) -> DomainResult<std::sync::MutexGuard<'_, Vec<ProxyEngineEvent>>> {
        self.lifecycle_events
            .lock()
            .map_err(|_| lifecycle_state_error())
    }

    pub(crate) fn record_events(&self, events: Vec<ProxyEngineEvent>) -> DomainResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        self.lifecycle_event_state()?.extend(events);
        Ok(())
    }

    pub(crate) fn start_runtime_handle(
        &self,
        engine_config: &ProxyEngineConfig,
    ) -> DomainResult<NativeRuntimeHandle> {
        let plan = NativeRuntimeAssemblyPlan::from_config(engine_config)?;
        let assembly = match plan
            .start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
                self.http_mitm_hook.clone(),
                self.tls_mitm_ca_material.clone(),
            ) {
            Ok(assembly) => assembly,
            Err(failure) => {
                let NativeRuntimeStartupFailure { error, release } = *failure;
                self.record_events(release.events)?;
                return Err(error);
            }
        };

        assembly.finish()
    }
}

pub fn assess_native_proxy_engine_start_readiness(
    engine_config: &ProxyEngineConfig,
) -> NativeProxyEngineStartReadinessReport {
    let service = NativeProxyEngineService::new();
    let mut diagnostics = service.validate_config(engine_config);
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return NativeProxyEngineStartReadinessReport {
            readiness: NativeProxyEngineStartReadiness::Blocked,
            diagnostics,
        };
    }

    match NativeRuntimeAssemblyPlan::from_config(engine_config) {
        Ok(_plan) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE,
                "native runtime assembly plan is ready for service start evaluation",
                SOURCE_ENGINE_NATIVE_LIFECYCLE,
            ));
            return NativeProxyEngineStartReadinessReport {
                readiness: NativeProxyEngineStartReadiness::Ready,
                diagnostics,
            };
        }
        Err(error) => diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Error,
            error.code,
            error.message,
            SOURCE_ENGINE_NATIVE_RUNTIME,
        )),
    }

    NativeProxyEngineStartReadinessReport {
        readiness: NativeProxyEngineStartReadiness::Blocked,
        diagnostics,
    }
}

impl ProxyEngineService for NativeProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_NATIVE_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::Native,
            version: None,
            capabilities: Vec::new(),
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if engine_config.engine_id != DEFAULT_NATIVE_ENGINE_ID {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
                "native proxy engine only supports the native engine id",
                SOURCE_ENGINE_NATIVE_CONFIG,
            ));
        }

        validate_listeners(engine_config, &mut diagnostics);
        validate_nodes(engine_config, &mut diagnostics);
        validate_routes(engine_config, &mut diagnostics);

        diagnostics
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;
        let readiness = assess_native_proxy_engine_start_readiness(engine_config);
        if readiness.readiness == NativeProxyEngineStartReadiness::Blocked {
            let diagnostic = readiness
                .diagnostics
                .into_iter()
                .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
                .unwrap_or_else(|| {
                    engine_diagnostic(
                        DiagnosticSeverity::Error,
                        ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
                        "native proxy runtime service start is unavailable",
                        SOURCE_ENGINE_NATIVE_LIFECYCLE,
                    )
                });

            return Err(domain_error(diagnostic.code, diagnostic.message));
        }

        {
            let runtime = self.runtime_state()?;
            if let Some(runtime) = runtime.as_ref() {
                return Ok(running_status(&runtime.handle));
            }
        }

        let handle = self.start_runtime_handle(engine_config)?;
        let status = running_status(&handle);
        let start_events = handle.events().to_vec();

        let mut runtime = self.runtime_state()?;
        if let Some(existing_runtime) = runtime.as_ref() {
            let status = running_status(&existing_runtime.handle);
            drop(runtime);
            let _ = handle.release();
            return Ok(status);
        }

        self.lifecycle_event_state()?.extend(start_events);
        *runtime = Some(NativeManagedRuntime {
            handle,
            config: engine_config.clone(),
        });

        Ok(status)
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;
        let readiness = assess_native_proxy_engine_start_readiness(engine_config);
        if readiness.readiness == NativeProxyEngineStartReadiness::Blocked {
            let diagnostic = readiness
                .diagnostics
                .into_iter()
                .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
                .unwrap_or_else(|| {
                    engine_diagnostic(
                        DiagnosticSeverity::Error,
                        ENGINE_NATIVE_RELOAD_FAILED_CODE,
                        "native proxy runtime reload configuration is unavailable",
                        SOURCE_ENGINE_NATIVE_LIFECYCLE,
                    )
                });
            return Err(domain_error(diagnostic.code, diagnostic.message));
        }

        let previous = {
            let mut runtime = self.runtime_state()?;
            runtime.take()
        };
        let Some(previous) = previous else {
            return Err(domain_error(
                ENGINE_NATIVE_RELOAD_RUNTIME_MISSING_CODE,
                "native proxy runtime reload requires a running current-process runtime",
            ));
        };

        let previous_config = previous.config;
        let release = previous.handle.release();
        if let Some(event) = release.events.last().cloned() {
            self.record_events(vec![event])?;
        }

        match self.start_runtime_handle(engine_config) {
            Ok(handle) => {
                let start_events = handle.events().to_vec();
                let status = reloaded_status(&handle);
                *self.runtime_state()? = Some(NativeManagedRuntime {
                    handle,
                    config: engine_config.clone(),
                });
                self.record_events(start_events)?;
                self.record_events(vec![runtime_event(
                    &engine_config.engine_id,
                    ProxyEngineEventKind::Reloaded,
                    vec![engine_diagnostic(
                        DiagnosticSeverity::Info,
                        ENGINE_NATIVE_RELOAD_RUNNING_CODE,
                        "native proxy runtime reloaded in the current process",
                        SOURCE_ENGINE_NATIVE_LIFECYCLE,
                    )],
                )])?;
                Ok(status)
            }
            Err(_) => match self.start_runtime_handle(&previous_config) {
                Ok(handle) => {
                    let rollback_events = handle.events().to_vec();
                    *self.runtime_state()? = Some(NativeManagedRuntime {
                        handle,
                        config: previous_config,
                    });
                    self.record_events(rollback_events)?;
                    Err(domain_error(
                        ENGINE_NATIVE_RELOAD_FAILED_CODE,
                        "native proxy runtime reload failed; previous configuration was restored",
                    ))
                }
                Err(_) => Err(domain_error(
                    ENGINE_NATIVE_RELOAD_ROLLBACK_FAILED_CODE,
                    "native proxy runtime reload failed and previous configuration could not be restored",
                )),
            },
        }
    }

    fn rollback(&self, request: &ProxyEngineRollbackRequest) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&request.snapshot.engine_id)?;
        if request.snapshot.engine_id != request.snapshot.config.engine_id {
            return Err(domain_error(
                ENGINE_NATIVE_RELOAD_ROLLBACK_FAILED_CODE,
                "native proxy rollback snapshot engine identity is inconsistent",
            ));
        }

        let current = self.status(&request.snapshot.engine_id)?;
        if current.state != request.expected_state {
            return Err(domain_error(
                ENGINE_NATIVE_RELOAD_ROLLBACK_FAILED_CODE,
                "native proxy rollback current lifecycle state does not match the expected state",
            ));
        }

        if current.state == ProxyEngineLifecycleState::Running {
            let _ = self.stop(&request.snapshot.engine_id)?;
        }

        if request.snapshot.status.state == ProxyEngineLifecycleState::Stopped {
            return Ok(stopped_status(&request.snapshot.engine_id));
        }

        match self.start_runtime_handle(&request.snapshot.config) {
            Ok(handle) => {
                let status = running_status(&handle);
                let events = handle.events().to_vec();
                *self.runtime_state()? = Some(NativeManagedRuntime {
                    handle,
                    config: request.snapshot.config.clone(),
                });
                self.record_events(events)?;
                Ok(status)
            }
            Err(error) => Err(domain_error(
                ENGINE_NATIVE_RELOAD_ROLLBACK_FAILED_CODE,
                format!("native proxy rollback failed: {}", error.message),
            )),
        }
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        let handle = {
            let mut runtime = self.runtime_state()?;
            runtime.take()
        };
        let Some(handle) = handle else {
            return Ok(stopped_status(engine_id));
        };

        let release = handle.handle.release();
        let release_event = release.events.last().cloned();
        let status = ProxyEngineStatus {
            engine_id: release.engine_id.clone(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: release.diagnostics.clone(),
        };
        if let Some(release_event) = release_event {
            self.record_events(vec![release_event])?;
        }

        Ok(status)
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        {
            let runtime = self.runtime_state()?;
            if let Some(runtime) = runtime.as_ref() {
                return Ok(runtime.handle.foreground_handoff_status());
            }
        }

        Ok(stopped_status(engine_id))
    }

    fn health(&self, engine_id: &str) -> DomainResult<ProxyEngineHealthReport> {
        ensure_native_engine_id(engine_id)?;

        let runtime = self.runtime_state()?;
        let Some(runtime) = runtime.as_ref() else {
            return Ok(ProxyEngineHealthReport {
                engine_id: engine_id.to_string(),
                state: ProxyEngineLifecycleState::Stopped,
                config_validated: false,
                runtime_resources_ready: false,
                listener_reachable: false,
                diagnostics: vec![engine_diagnostic(
                    DiagnosticSeverity::Warning,
                    ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
                    "native proxy runtime health probe found no active runtime resources",
                    SOURCE_ENGINE_NATIVE_RUNTIME,
                )],
            });
        };

        let config_validated = !self
            .validate_config(&runtime.config)
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error);
        let listener_address = runtime
            .handle
            .accept_loops()
            .first()
            .map(|listener| format!("{}:{}", listener.local_host(), listener.local_port()));
        let listener_reachable = listener_address
            .as_deref()
            .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
            .and_then(|address| {
                TcpStream::connect_timeout(&address, Duration::from_millis(250)).ok()
            })
            .is_some();

        Ok(ProxyEngineHealthReport {
            engine_id: engine_id.to_string(),
            state: runtime.handle.foreground_handoff_status().state,
            config_validated,
            runtime_resources_ready: true,
            listener_reachable,
            diagnostics: vec![engine_diagnostic(
                if config_validated && listener_reachable {
                    DiagnosticSeverity::Info
                } else {
                    DiagnosticSeverity::Warning
                },
                if config_validated && listener_reachable {
                    ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE
                } else {
                    ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE
                },
                if config_validated && listener_reachable {
                    "native proxy runtime health checks confirmed configuration and loopback listener reachability"
                } else {
                    "native proxy runtime health checks did not confirm every readiness condition"
                },
                SOURCE_ENGINE_NATIVE_RUNTIME,
            )],
        })
    }

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        ensure_native_engine_id(engine_id)?;

        Ok(self.lifecycle_event_state()?.clone())
    }
}

pub(crate) fn running_status(handle: &NativeRuntimeHandle) -> ProxyEngineStatus {
    let mut status = handle.foreground_handoff_status();
    status.diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_START_RUNNING_CODE,
        "native proxy runtime is running in the current process",
        SOURCE_ENGINE_NATIVE_LIFECYCLE,
    ));
    status
}

pub(crate) fn reloaded_status(handle: &NativeRuntimeHandle) -> ProxyEngineStatus {
    let mut status = running_status(handle);
    status.diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RELOAD_RUNNING_CODE,
        "native proxy runtime reloaded in the current process",
        SOURCE_ENGINE_NATIVE_LIFECYCLE,
    ));
    status
}

pub(crate) fn stopped_status(engine_id: &str) -> ProxyEngineStatus {
    ProxyEngineStatus {
        engine_id: engine_id.to_string(),
        state: ProxyEngineLifecycleState::Stopped,
        diagnostics: Vec::new(),
    }
}

pub(crate) fn lifecycle_state_error() -> DomainError {
    domain_error(
        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
        "native proxy runtime lifecycle state is unavailable",
    )
}
