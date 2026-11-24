//! The managed foreground session: its status and event files, the
//! lifecycle recorder and the managed control socket.

use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandManagedForegroundSessionStore;

impl CommandManagedForegroundSessionStore {
    pub const fn new() -> Self {
        Self
    }

    pub fn read_status(
        &self,
        request: &ManagedForegroundSessionStatusRequest,
    ) -> DomainResult<ManagedForegroundSessionStatusReport> {
        let status_path = required_managed_foreground_status_path(&request.status_path)?;
        let (record, _) = read_managed_foreground_session_status_file(&status_path)?;

        Ok(ManagedForegroundSessionStatusReport {
            status_path,
            session_id: record.session_id.trim().to_string(),
            engine_id: record.engine_id.trim().to_string(),
            state: record.state.trim().to_string(),
            liveness_verified: false,
        })
    }

    pub fn write_status(
        &self,
        request: &ManagedForegroundSessionStatusWriteRequest,
    ) -> DomainResult<ManagedForegroundSessionStatusWriteReport> {
        let status_path = required_managed_foreground_status_path(&request.status_path)?;
        let record = ManagedForegroundSessionStatusFile {
            schema_version: MANAGED_FOREGROUND_SESSION_STATUS_SCHEMA_VERSION,
            session_id: request.session_id.trim().to_string(),
            engine_id: request.engine_id.trim().to_string(),
            state: request.state.trim().to_string(),
        };
        validate_managed_foreground_session_status_file(&record)?;
        let record_json = serde_json::to_string_pretty(&record).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE,
                format!("failed to render managed foreground status record: {error}"),
            )
        })?;
        write_new_file(
            &status_path,
            record_json.as_bytes(),
            CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE,
            "managed foreground status record",
        )?;

        Ok(ManagedForegroundSessionStatusWriteReport {
            status_path,
            session_id: record.session_id,
            engine_id: record.engine_id,
            state: record.state,
            record_written: true,
            liveness_verified: false,
        })
    }

    pub fn transition_status(
        &self,
        request: &ManagedForegroundSessionStatusTransitionRequest,
    ) -> DomainResult<ManagedForegroundSessionStatusTransitionReport> {
        let status_path = required_managed_foreground_status_path(&request.status_path)?;
        let snapshot_path =
            required_managed_foreground_status_snapshot_path(&request.snapshot_path)?;
        if status_path == snapshot_path {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_PATH_CONFLICT_CODE,
                "managed foreground status and snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing managed foreground status snapshot",
            ));
        }

        let expected_state = required_managed_foreground_status_state(
            &request.expected_state,
            CLI_MANAGED_FOREGROUND_STATUS_TRANSITION_INVALID_CODE,
            "managed foreground expected state is unsupported",
        )?;
        let next_state = required_managed_foreground_status_state(
            &request.next_state,
            CLI_MANAGED_FOREGROUND_STATUS_TRANSITION_INVALID_CODE,
            "managed foreground next state is unsupported",
        )?;
        let (mut record, previous_contents) =
            read_managed_foreground_session_status_file(&status_path)?;
        let previous_state = record.state.trim().to_string();
        if previous_state != expected_state {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_STATE_CONFLICT_CODE,
                "managed foreground status record did not match the expected state",
            ));
        }
        if !is_managed_foreground_status_transition_allowed(&previous_state, &next_state) {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_TRANSITION_INVALID_CODE,
                "managed foreground status transition is not allowed",
            ));
        }
        record.state = next_state.clone();
        let current_contents = serde_json::to_string_pretty(&record).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE,
                format!("failed to render managed foreground status record: {error}"),
            )
        })?;
        write_new_file(
            &snapshot_path,
            previous_contents.as_bytes(),
            CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_WRITE_FAILED_CODE,
            "managed foreground status snapshot",
        )?;
        write_replace_file(
            &status_path,
            current_contents.as_bytes(),
            CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE,
            "managed foreground status record",
        )?;

        Ok(ManagedForegroundSessionStatusTransitionReport {
            status_path,
            snapshot_path,
            session_id: record.session_id.trim().to_string(),
            engine_id: record.engine_id.trim().to_string(),
            previous_state,
            state: next_state,
            snapshot_written: true,
            liveness_verified: false,
        })
    }

    pub fn rollback_status(
        &self,
        request: &ManagedForegroundSessionStatusRollbackRequest,
    ) -> DomainResult<ManagedForegroundSessionStatusRollbackReport> {
        let status_path = required_managed_foreground_status_path(&request.status_path)?;
        let snapshot_path =
            required_managed_foreground_status_snapshot_path(&request.snapshot_path)?;
        if status_path == snapshot_path {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_PATH_CONFLICT_CODE,
                "managed foreground status and rollback snapshot paths must differ",
            ));
        }

        let expected_state = required_managed_foreground_status_state(
            &request.expected_state,
            CLI_MANAGED_FOREGROUND_STATUS_ROLLBACK_INVALID_CODE,
            "managed foreground rollback expected state is unsupported",
        )?;
        let (current_record, _) = read_managed_foreground_session_status_file(&status_path)?;
        let previous_state = current_record.state.trim().to_string();
        if previous_state != expected_state {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_STATE_CONFLICT_CODE,
                "managed foreground status record did not match the expected rollback state",
            ));
        }

        let (snapshot_record, snapshot_contents) =
            read_managed_foreground_session_status_snapshot_file(&snapshot_path)?;
        if current_record.session_id.trim() != snapshot_record.session_id.trim()
            || current_record.engine_id.trim() != snapshot_record.engine_id.trim()
        {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_ROLLBACK_INVALID_CODE,
                "managed foreground rollback snapshot does not match the status record session",
            ));
        }

        write_replace_file(
            &status_path,
            snapshot_contents.as_bytes(),
            CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE,
            "managed foreground status record",
        )?;

        Ok(ManagedForegroundSessionStatusRollbackReport {
            status_path,
            snapshot_path,
            session_id: snapshot_record.session_id.trim().to_string(),
            engine_id: snapshot_record.engine_id.trim().to_string(),
            previous_state,
            state: snapshot_record.state.trim().to_string(),
            snapshot_retained: true,
            liveness_verified: false,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandManagedForegroundSessionEventStore;

impl CommandManagedForegroundSessionEventStore {
    pub const fn new() -> Self {
        Self
    }

    pub fn read_event(
        &self,
        request: &ManagedForegroundSessionEventRequest,
    ) -> DomainResult<ManagedForegroundSessionEventReport> {
        let event_path = required_managed_foreground_event_path(&request.event_path)?;
        let record = read_managed_foreground_session_event_file(&event_path)?;

        Ok(ManagedForegroundSessionEventReport {
            event_path,
            session_id: record.session_id.trim().to_string(),
            engine_id: record.engine_id.trim().to_string(),
            event_id: record.event_id.trim().to_string(),
            event_kind: record.event_kind.trim().to_string(),
            state: record.state.trim().to_string(),
            recorded_at: record.recorded_at.trim().to_string(),
            liveness_verified: false,
        })
    }

    pub fn list_event_history(
        &self,
        request: &ManagedForegroundSessionEventHistoryRequest,
    ) -> DomainResult<ManagedForegroundSessionEventHistoryReport> {
        let event_directory =
            required_managed_foreground_event_directory_path(&request.event_directory)?;
        let session_id =
            optional_managed_foreground_event_history_session_id(request.session_id.as_deref())?;
        let event_kind =
            optional_managed_foreground_event_history_kind(request.event_kind.as_deref())?;
        let state = optional_managed_foreground_event_history_state(request.state.as_deref())?;
        let limit = required_managed_foreground_event_history_limit(request.limit)?;
        let event_paths = managed_foreground_event_history_paths(&event_directory)?;
        let mut events = Vec::with_capacity(event_paths.len());

        for path in event_paths {
            let event_path = path.to_str().ok_or_else(|| {
                DomainError::new(
                    CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
                    format!(
                        "managed foreground event record path is not valid UTF-8: {}",
                        path.display()
                    ),
                )
            })?;
            let record = read_managed_foreground_session_event_history_file(event_path)?;
            let entry = ManagedForegroundSessionEventHistoryEntry {
                event_path: event_path.to_string(),
                session_id: record.session_id.trim().to_string(),
                engine_id: record.engine_id.trim().to_string(),
                event_id: record.event_id.trim().to_string(),
                event_kind: record.event_kind.trim().to_string(),
                state: record.state.trim().to_string(),
                recorded_at: record.recorded_at.trim().to_string(),
            };
            if session_id
                .as_ref()
                .is_none_or(|requested| entry.session_id == *requested)
                && event_kind
                    .as_ref()
                    .is_none_or(|requested| entry.event_kind == *requested)
                && state
                    .as_ref()
                    .is_none_or(|requested| entry.state == *requested)
            {
                events.push(entry);
            }
        }

        events.sort_by(|left, right| {
            (
                left.recorded_at.as_str(),
                left.event_id.as_str(),
                left.event_path.as_str(),
            )
                .cmp(&(
                    right.recorded_at.as_str(),
                    right.event_id.as_str(),
                    right.event_path.as_str(),
                ))
        });

        let matching_event_count = events.len();
        let cursor = request.cursor.min(matching_event_count);
        let end = cursor.saturating_add(limit).min(matching_event_count);
        let next_cursor = (end < matching_event_count).then_some(end);
        let events = events[cursor..end].to_vec();

        Ok(ManagedForegroundSessionEventHistoryReport {
            event_directory,
            session_id,
            event_kind,
            state,
            cursor,
            next_cursor,
            matching_event_count,
            events,
            liveness_verified: false,
        })
    }

    pub fn write_event(
        &self,
        request: &ManagedForegroundSessionEventWriteRequest,
    ) -> DomainResult<ManagedForegroundSessionEventWriteReport> {
        let event_path = required_managed_foreground_event_path(&request.event_path)?;
        let record = ManagedForegroundSessionEventFile {
            schema_version: MANAGED_FOREGROUND_SESSION_EVENT_SCHEMA_VERSION,
            session_id: request.session_id.trim().to_string(),
            engine_id: request.engine_id.trim().to_string(),
            event_id: request.event_id.trim().to_string(),
            event_kind: request.event_kind.trim().to_string(),
            state: request.state.trim().to_string(),
            recorded_at: request.recorded_at.trim().to_string(),
        };
        validate_managed_foreground_session_event_file(&record)?;
        let record_json = serde_json::to_string_pretty(&record).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_WRITE_FAILED_CODE,
                format!("failed to render managed foreground event record: {error}"),
            )
        })?;
        write_new_file(
            &event_path,
            record_json.as_bytes(),
            CLI_MANAGED_FOREGROUND_EVENT_WRITE_FAILED_CODE,
            "managed foreground event record",
        )?;

        Ok(ManagedForegroundSessionEventWriteReport {
            event_path,
            session_id: record.session_id,
            engine_id: record.engine_id,
            event_id: record.event_id,
            event_kind: record.event_kind,
            state: record.state,
            recorded_at: record.recorded_at,
            record_written: true,
            liveness_verified: false,
        })
    }
}

pub(crate) struct ManagedForegroundLifecycleRecorder {
    pub(crate) paths: ManagedForegroundLifecyclePaths,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
}

impl ManagedForegroundLifecycleRecorder {
    pub(crate) fn new(paths: ManagedForegroundLifecyclePaths) -> DomainResult<Self> {
        let status_path = paths.status_path.trim();
        let snapshot_path = paths.snapshot_path.trim();
        let event_directory = paths.event_directory.trim();
        let control_socket_path = paths
            .control_socket_path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(ToString::to_string);
        if status_path.is_empty() || snapshot_path.is_empty() || event_directory.is_empty() {
            return Err(DomainError::new(
                CLI_START_MANAGED_LIFECYCLE_CONFIG_INVALID_CODE,
                "managed foreground lifecycle paths must all be non-empty",
            ));
        }
        if paths
            .control_socket_path
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(DomainError::new(
                CLI_START_MANAGED_LIFECYCLE_CONFIG_INVALID_CODE,
                "managed foreground control socket path cannot be empty",
            ));
        }
        if status_path == snapshot_path {
            return Err(DomainError::new(
                CLI_START_MANAGED_LIFECYCLE_CONFIG_INVALID_CODE,
                "managed foreground status and snapshot paths must differ",
            ));
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        Ok(Self {
            paths: ManagedForegroundLifecyclePaths {
                status_path: status_path.to_string(),
                snapshot_path: snapshot_path.to_string(),
                event_directory: event_directory.to_string(),
                control_socket_path,
            },
            session_id: format!("foreground-{}-{timestamp}", std::process::id()),
            engine_id: DEFAULT_ENGINE_ID.to_string(),
        })
    }

    pub(crate) fn event_path(&self, event_id: &str) -> String {
        std::path::Path::new(&self.paths.event_directory)
            .join(format!("{}.json", event_id))
            .display()
            .to_string()
    }

    pub(crate) fn recorded_at(&self) -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos().to_string())
            .unwrap_or_else(|_| "0".to_string())
    }

    pub(crate) fn write_event(
        &self,
        event_id: &str,
        event_kind: &str,
        state: &str,
    ) -> DomainResult<()> {
        CommandManagedForegroundSessionEventStore::new()
            .write_event(&ManagedForegroundSessionEventWriteRequest {
                event_path: self.event_path(event_id),
                session_id: self.session_id.clone(),
                engine_id: self.engine_id.clone(),
                event_id: event_id.to_string(),
                event_kind: event_kind.to_string(),
                state: state.to_string(),
                recorded_at: self.recorded_at(),
            })
            .map(|_| ())
    }

    pub(crate) fn initialize(&self) -> DomainResult<()> {
        CommandManagedForegroundSessionStore::new().write_status(
            &ManagedForegroundSessionStatusWriteRequest {
                status_path: self.paths.status_path.clone(),
                session_id: self.session_id.clone(),
                engine_id: self.engine_id.clone(),
                state: "starting".to_string(),
            },
        )?;
        self.write_event(
            &format!("{}-session-started", self.session_id),
            "session_started",
            "starting",
        )
    }

    pub(crate) fn transition(
        &self,
        expected_state: &str,
        next_state: &str,
        snapshot_path: String,
    ) -> DomainResult<()> {
        CommandManagedForegroundSessionStore::new().transition_status(
            &ManagedForegroundSessionStatusTransitionRequest {
                status_path: self.paths.status_path.clone(),
                snapshot_path,
                expected_state: expected_state.to_string(),
                next_state: next_state.to_string(),
            },
        )?;
        let (event_kind, event_suffix) = match next_state {
            "running" => ("status_transition", "running"),
            "stopped" => ("session_stopped", "stopped"),
            "failed" => ("session_failed", "failed"),
            _ => ("status_transition", next_state),
        };
        self.write_event(
            &format!("{}-{}", self.session_id, event_suffix),
            event_kind,
            next_state,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedControlRequest {
    Stop,
    Reload,
    Rollback { expected_config_version: u64 },
}

impl ManagedControlRequest {
    pub(crate) const fn wire_command(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Reload => "reload",
            Self::Rollback { .. } => "rollback",
        }
    }

    #[cfg(unix)]
    pub(crate) const fn signal_value(self) -> u8 {
        match self {
            Self::Stop => MANAGED_CONTROL_STOP,
            Self::Reload => MANAGED_CONTROL_RELOAD,
            Self::Rollback { .. } => MANAGED_CONTROL_ROLLBACK,
        }
    }
}

pub trait ManagedControlInterrupter: Send + Sync {
    fn interrupt(&self, request: ManagedControlRequest) -> DomainResult<()>;
}

#[derive(Debug, Clone, Default)]
pub struct ManagedRuntimeHealthSnapshot {
    pub record: String,
    pub config_version: u64,
}

pub(crate) fn record_managed_runtime_health(
    snapshot: &Arc<Mutex<ManagedRuntimeHealthSnapshot>>,
    health: &ProxyEngineHealthReport,
    config_digest: &str,
    config_version: u64,
) {
    if let Ok(mut snapshot) = snapshot.lock() {
        snapshot.config_version = config_version;
        snapshot.record = format!(
            "pid={} engine_id={} state={:?} config_version={} config_digest={} config_validated={} runtime_resources_ready={} listener_reachable={} control_readback=true",
            std::process::id(),
            health.engine_id,
            health.state,
            config_version,
            config_digest,
            health.config_validated,
            health.runtime_resources_ready,
            health.listener_reachable,
        );
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsSignalManagedControlInterrupter;

impl ManagedControlInterrupter for OsSignalManagedControlInterrupter {
    fn interrupt(&self, _request: ManagedControlRequest) -> DomainResult<()> {
        #[cfg(unix)]
        {
            if MANAGED_CONTROL_REQUEST
                .compare_exchange(
                    MANAGED_CONTROL_NONE,
                    MANAGED_CONTROL_PENDING,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_err()
            {
                return Err(DomainError::new(
                    CLI_MANAGED_CONTROL_SOCKET_REQUEST_PENDING_CODE,
                    "managed foreground control request is already pending",
                ));
            }
            if let ManagedControlRequest::Rollback {
                expected_config_version,
            } = _request
            {
                MANAGED_CONTROL_EXPECTED_CONFIG_VERSION
                    .store(expected_config_version, Ordering::SeqCst);
            } else {
                MANAGED_CONTROL_EXPECTED_CONFIG_VERSION.store(0, Ordering::SeqCst);
            }
            MANAGED_CONTROL_REQUEST.store(_request.signal_value(), Ordering::SeqCst);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(DomainError::new(
                CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                "managed foreground control sockets require Unix",
            ))
        }
    }
}

pub struct ManagedControlSocketGuard {
    #[cfg(unix)]
    pub(crate) socket_path: String,
    #[cfg(unix)]
    pub(crate) shutdown: mpsc::Sender<()>,
    #[cfg(unix)]
    pub(crate) worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ManagedControlSocketGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = self.shutdown.send(());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            if std::fs::symlink_metadata(&self.socket_path)
                .is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                let _ = std::fs::remove_file(&self.socket_path);
            }
        }
    }
}

pub fn start_managed_control_socket(socket_path: &str) -> DomainResult<ManagedControlSocketGuard> {
    #[cfg(unix)]
    {
        MANAGED_CONTROL_REQUEST.store(MANAGED_CONTROL_NONE, Ordering::SeqCst);
        MANAGED_CONTROL_EXPECTED_CONFIG_VERSION.store(0, Ordering::SeqCst);
    }
    start_managed_control_socket_with_interrupter(
        socket_path,
        Arc::new(OsSignalManagedControlInterrupter),
    )
}

pub fn start_managed_control_socket_with_interrupter(
    socket_path: &str,
    interrupter: Arc<dyn ManagedControlInterrupter>,
) -> DomainResult<ManagedControlSocketGuard> {
    start_managed_control_socket_with_runtime_snapshot(socket_path, interrupter, None)
}

pub fn start_managed_control_socket_with_runtime_snapshot(
    socket_path: &str,
    interrupter: Arc<dyn ManagedControlInterrupter>,
    _runtime_snapshot: Option<Arc<Mutex<ManagedRuntimeHealthSnapshot>>>,
) -> DomainResult<ManagedControlSocketGuard> {
    let socket_path = socket_path.trim();
    if socket_path.is_empty() || !std::path::Path::new(socket_path).is_absolute() {
        return Err(DomainError::new(
            CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
            "managed foreground control socket path must be absolute",
        ));
    }
    #[cfg(unix)]
    {
        MANAGED_CONTROL_REQUEST.store(MANAGED_CONTROL_NONE, Ordering::SeqCst);
        MANAGED_CONTROL_EXPECTED_CONFIG_VERSION.store(0, Ordering::SeqCst);
        if std::path::Path::new(socket_path).exists() {
            return Err(DomainError::new(
                CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                "refusing to replace an existing managed foreground control socket path",
            ));
        }
        write_parent_dir(socket_path, CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE)?;
        let listener = UnixListener::bind(socket_path).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                format!("failed to bind managed foreground control socket: {error}"),
            )
        })?;
        if let Err(error) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(socket_path);
            return Err(DomainError::new(
                CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                format!("failed to protect managed foreground control socket: {error}"),
            ));
        }
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = std::fs::remove_file(socket_path);
            return Err(DomainError::new(
                CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                format!("failed to configure managed foreground control socket: {error}"),
            ));
        }
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || loop {
            if shutdown_receiver.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut command = Vec::new();
                    // Accepted sockets inherit O_NONBLOCK from the listener on
                    // BSD-derived kernels; the bounded read relies on a blocking
                    // socket with a read timeout.
                    let read_result = stream
                        .set_nonblocking(false)
                        .and_then(|()| {
                            stream.set_read_timeout(Some(Duration::from_secs(
                                MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
                            )))
                        })
                        .and_then(|()| (&mut stream).take(64).read_to_end(&mut command));
                    let wire_command = read_result.ok().and_then(|_| {
                        std::str::from_utf8(&command)
                            .ok()
                            .map(|value| value.trim().to_string())
                    });
                    let request = wire_command.as_deref().and_then(|value| {
                        let mut fields = value.split_ascii_whitespace();
                        match (fields.next(), fields.next(), fields.next()) {
                            (Some("stop"), None, None) => Some(ManagedControlRequest::Stop),
                            (Some("reload"), None, None) => Some(ManagedControlRequest::Reload),
                            (Some("rollback"), Some(version), None) => version
                                .parse::<u64>()
                                .ok()
                                .filter(|version| *version > 0)
                                .map(|expected_config_version| ManagedControlRequest::Rollback {
                                    expected_config_version,
                                }),
                            _ => None,
                        }
                    });
                    if wire_command.as_deref() == Some("status") {
                        let snapshot = _runtime_snapshot
                            .as_ref()
                            .and_then(|snapshot| {
                                snapshot.lock().ok().map(|value| value.record.clone())
                            })
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| {
                                "state=unavailable error_code=runtime_status_unavailable"
                                    .to_string()
                            });
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(
                            MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
                        )));
                        let _ = stream.write_all(format!("status {snapshot}\n").as_bytes());
                        continue;
                    }
                    let (response, accepted) = match request {
                        Some(request) => match interrupter.interrupt(request) {
                            Ok(()) => (b"accepted\n".as_slice(), true),
                            Err(error)
                                if error.code
                                    == CLI_MANAGED_CONTROL_SOCKET_REQUEST_PENDING_CODE =>
                            {
                                (b"rejected request_pending\n".as_slice(), false)
                            }
                            Err(_) => (b"rejected\n".as_slice(), false),
                        },
                        None => (b"rejected\n".as_slice(), false),
                    };
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(
                        MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
                    )));
                    let _ = stream.write_all(response);
                    if accepted && request == Some(ManagedControlRequest::Stop) {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        });
        Ok(ManagedControlSocketGuard {
            socket_path: socket_path.to_string(),
            shutdown,
            worker: Some(worker),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = interrupter;
        Err(DomainError::new(
            CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
            "managed foreground control sockets require Unix",
        ))
    }
}

/// Source-only file boundary for caller-selected managed runtime logs.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommandManagedForegroundSessionLogStore;

impl CommandManagedForegroundSessionLogStore {
    pub const fn new() -> Self {
        Self
    }

    pub fn read_tail(
        &self,
        request: &ManagedForegroundSessionLogTailRequest,
    ) -> DomainResult<ManagedForegroundSessionLogTailReport> {
        let log_path = required_managed_foreground_log_path(&request.log_path)?;
        let line_limit = required_managed_foreground_log_tail_limit(request.line_limit)?;
        let metadata = std::fs::metadata(&log_path).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_LOG_READ_FAILED_CODE,
                format!("failed to inspect managed foreground log {log_path}: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_LOG_READ_FAILED_CODE,
                "managed foreground log path must refer to a regular file",
            ));
        }
        if metadata.len() > MANAGED_FOREGROUND_LOG_TAIL_MAX_BYTES {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_LOG_LIMIT_EXCEEDED_CODE,
                format!(
                    "managed foreground log {log_path} exceeds the {} byte tail limit",
                    MANAGED_FOREGROUND_LOG_TAIL_MAX_BYTES
                ),
            ));
        }
        let contents = std::fs::read_to_string(&log_path).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_LOG_READ_FAILED_CODE,
                format!("failed to read managed foreground log {log_path}: {error}"),
            )
        })?;
        let total_line_count = contents.lines().count();
        let skip = total_line_count.saturating_sub(line_limit);
        let lines: Vec<String> = contents
            .lines()
            .skip(skip)
            .map(redact_cli_output_text)
            .collect();
        let returned_byte_count = lines.iter().map(String::len).sum();

        Ok(ManagedForegroundSessionLogTailReport {
            log_path,
            line_limit,
            total_line_count,
            lines,
            returned_byte_count,
            liveness_verified: false,
        })
    }
}
