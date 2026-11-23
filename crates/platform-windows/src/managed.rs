//! Durable configuration and state shared by the Windows GUI and service host.

use crate::managed_files::{
    ensure_managed_directory, is_within_managed_root, read_managed_file,
    windows_managed_root_directory, write_managed_file_atomic,
};
use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION: u32 = 2;
const WINDOWS_MANAGED_CONFIG_LEGACY_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MANAGED_STATE_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MANAGED_CONFIG_INVALID_CODE: &str = "windows.managed.config_invalid";
pub const WINDOWS_MANAGED_CONFIG_IO_CODE: &str = "windows.managed.config_io_failed";
pub const WINDOWS_MANAGED_STATE_IO_CODE: &str = "windows.managed.state_io_failed";
pub const WINDOWS_MANAGED_NATIVE_MITM_CONFIG_INVALID_CODE: &str =
    "windows.managed.native_mitm_config_invalid";
pub const WINDOWS_MANAGED_EMBEDDED_CONFIG_INVALID_CODE: &str =
    "windows.managed.embedded_config_invalid";
pub const WINDOWS_MANAGED_PRODUCT_DIRECTORY: &str = "AnixOps\\NetworkCore";
pub const WINDOWS_MANAGED_CONFIG_FILE_NAME: &str = "managed-config.json";
pub const WINDOWS_MANAGED_STATE_FILE_NAME: &str = "managed-state.json";
pub const WINDOWS_MANAGED_LOG_DIRECTORY: &str = "logs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxySettings {
    pub enabled: bool,
    pub server: String,
    pub bypass: String,
}

impl WindowsProxySettings {
    pub fn validate(&self) -> DomainResult<()> {
        if self.enabled && self.server.trim().is_empty() {
            return Err(config_error("enabled system proxy requires a server"));
        }
        if self.server.contains('\0') || self.bypass.contains('\0') {
            return Err(config_error(
                "system proxy values contain an invalid character",
            ));
        }
        Ok(())
    }
}

/// Selects which runtime is allowed to mutate the current user's system
/// proxy for this managed configuration.
///
/// Existing schema-1 configurations intentionally default to `Service` so a
/// CLI- or service-managed deployment keeps its established rollback
/// behavior. The Windows GUI writes `Desktop` after importing a daily-use
/// profile and owns that per-user snapshot itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsSystemProxyOwner {
    #[default]
    Service,
    Desktop,
}

impl WindowsSystemProxyOwner {
    pub const fn is_service_managed(self) -> bool {
        matches!(self, Self::Service)
    }
}

/// The current user's system proxy as it was before an apply, and what the
/// apply wrote, so a restore puts back only what still holds this
/// client's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxySnapshot {
    /// The WinINet LAN values `ProxyEnable`, `ProxyServer`, `ProxyOverride`.
    pub enabled: bool,
    pub server: String,
    pub bypass: String,
    /// The machine-wide WinHTTP proxy as it was.
    pub winhttp_access_type: u32,
    pub winhttp_server: String,
    pub winhttp_bypass: String,
    /// Whether the apply left WinHTTP alone (every snapshot taken since
    /// 1.0). Older snapshots lack it (`false`): their apply also set WinHTTP
    /// to the applied proxy, which a restore undoes only while WinHTTP still
    /// holds exactly that value.
    #[serde(default)]
    pub winhttp_untouched: bool,
    /// The proxy the apply wrote; `None` in snapshots taken before 1.0.
    #[serde(default)]
    pub applied: Option<WindowsProxySettings>,
    /// Every WinINet connection's own settings as they were: the LAN and
    /// each dial-up / VPN (RAS) entry, including the automatic
    /// configuration script and automatic detection. Empty in snapshots
    /// taken before 1.0, whose restore only puts back the LAN values above.
    #[serde(default)]
    pub connections: Vec<WindowsConnectionProxySnapshot>,
}

/// One WinINet connection's proxy settings (`INTERNET_PER_CONN_*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsConnectionProxySnapshot {
    /// The dial-up / VPN entry name; `None` is the LAN connection.
    pub connection: Option<String>,
    /// `PROXY_TYPE_*` flags (direct, proxy, configuration script, detect).
    pub flags: u32,
    pub server: String,
    pub bypass: String,
    pub auto_config_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDriverPackageConfig {
    pub inf_path: PathBuf,
}

/// The in-process engine (engine-embedded): the profile's nodes behind a local
/// SOCKS5/HTTP listener, with no external engine binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedEmbeddedConfig {
    pub enabled: bool,
    /// engine-embedded configuration envelope (JSON).
    pub envelope_path: PathBuf,
    pub listen_host: String,
    pub listen_port: u16,
}

impl WindowsManagedEmbeddedConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let loopback = self
            .listen_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if self.envelope_path.as_os_str().is_empty() || !loopback || self.listen_port == 0 {
            return Err(DomainError::new(
                WINDOWS_MANAGED_EMBEDDED_CONFIG_INVALID_CODE,
                "enabled embedded engine requires an envelope path and a loopback listener",
            ));
        }
        Ok(())
    }

    /// The listener as `host:port`, as recorded in the managed state.
    pub fn listener(&self) -> String {
        std::net::SocketAddr::new(
            self.listen_host
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            self.listen_port,
        )
        .to_string()
    }
}

/// Native explicit HTTP proxy that terminates controlled HTTPS sessions before
/// relaying them through the embedded engine's local SOCKS listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedNativeMitmConfig {
    pub enabled: bool,
    pub listen_host: String,
    pub listen_port: u16,
    pub upstream_socks_host: String,
    pub upstream_socks_port: u16,
    pub ca_certificate_path: PathBuf,
    pub ca_private_key_path: PathBuf,
    pub log_path: PathBuf,
    /// Explicit local Node runner and script URL mappings for native MITM.
    #[serde(default)]
    pub script_runtime: Option<WindowsManagedNativeMitmScriptRuntimeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedNativeMitmScriptRuntimeConfig {
    pub policy_source_path: PathBuf,
    pub runner_path: PathBuf,
    pub node_binary: String,
    pub script_maps: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub persistent_store_path: Option<PathBuf>,
}

impl WindowsManagedNativeMitmScriptRuntimeConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.policy_source_path.as_os_str().is_empty()
            || self.runner_path.as_os_str().is_empty()
            || self.node_binary.trim().is_empty()
            || self.script_maps.is_empty()
            || self.script_maps.iter().any(|(url, path)| {
                !(url.starts_with("https://") || url.starts_with("http://"))
                    || path.as_os_str().is_empty()
            })
        {
            return Err(DomainError::new(
                WINDOWS_MANAGED_NATIVE_MITM_CONFIG_INVALID_CODE,
                "native MITM script runtime requires a local policy source, runner, Node binary, and HTTP(S) URL mappings",
            ));
        }
        Ok(())
    }
}

impl WindowsManagedNativeMitmConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.listen_host.trim().is_empty()
            || self.listen_port == 0
            || self.upstream_socks_host.trim().is_empty()
            || self.upstream_socks_port == 0
        {
            return Err(DomainError::new(
                WINDOWS_MANAGED_NATIVE_MITM_CONFIG_INVALID_CODE,
                "native MITM listener and SOCKS upstream endpoints must be explicit",
            ));
        }
        if self.ca_certificate_path.as_os_str().is_empty()
            || self.ca_private_key_path.as_os_str().is_empty()
            || self.log_path.as_os_str().is_empty()
        {
            return Err(DomainError::new(
                WINDOWS_MANAGED_NATIVE_MITM_CONFIG_INVALID_CODE,
                "native MITM certificate, private key, and log paths must be explicit",
            ));
        }
        if let Some(script_runtime) = &self.script_runtime {
            script_runtime.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedConfig {
    pub schema_version: u32,
    pub system_proxy: Option<WindowsProxySettings>,
    pub system_proxy_owner: WindowsSystemProxyOwner,
    pub root_certificate_path: Option<PathBuf>,
    pub driver_package: Option<WindowsDriverPackageConfig>,
    #[serde(default)]
    pub native_mitm: Option<WindowsManagedNativeMitmConfig>,
    #[serde(default)]
    pub embedded: Option<WindowsManagedEmbeddedConfig>,
}

impl WindowsManagedConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.schema_version != WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION {
            return Err(config_error(
                "unsupported managed configuration schema version",
            ));
        }
        if let Some(proxy) = &self.system_proxy {
            proxy.validate()?;
        }
        if let Some(path) = &self.root_certificate_path {
            if path.as_os_str().is_empty() {
                return Err(config_error("root certificate path must not be empty"));
            }
        }
        if let Some(driver) = &self.driver_package {
            if driver.inf_path.as_os_str().is_empty() {
                return Err(config_error("driver INF path must not be empty"));
            }
        }
        if let Some(embedded) = &self.embedded {
            embedded.validate()?;
        }
        if let Some(native_mitm) = &self.native_mitm {
            native_mitm.validate()?;
            if native_mitm.enabled && !self.system_proxy_owner.is_service_managed() {
                return Err(config_error(
                    "enabled native HTTPS MITM requires service-owned system proxy lifecycle",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedState {
    pub schema_version: u32,
    pub proxy_snapshot: Option<WindowsProxySnapshot>,
    pub certificate_sha1: Option<String>,
    pub driver_inf_path: Option<PathBuf>,
    pub driver_reboot_required: bool,
    #[serde(default)]
    pub native_mitm_running: bool,
    #[serde(default)]
    pub native_mitm_listener: Option<String>,
    #[serde(default)]
    pub native_mitm_certificate_sha1: Option<String>,
    #[serde(default)]
    pub native_mitm_last_error: Option<String>,
    #[serde(default)]
    pub embedded_running: bool,
    #[serde(default)]
    pub embedded_listener: Option<String>,
    #[serde(default)]
    pub embedded_last_error: Option<String>,
    /// Last service-owned runtime failure retained after cleanup so the GUI
    /// diagnostics can distinguish an operator-requested stop from a core exit.
    #[serde(default)]
    pub last_error: Option<String>,
    pub last_transition: String,
}

impl Default for WindowsManagedState {
    fn default() -> Self {
        Self {
            schema_version: WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
            proxy_snapshot: None,
            certificate_sha1: None,
            driver_inf_path: None,
            driver_reboot_required: false,
            native_mitm_running: false,
            native_mitm_listener: None,
            native_mitm_certificate_sha1: None,
            native_mitm_last_error: None,
            embedded_running: false,
            embedded_listener: None,
            embedded_last_error: None,
            last_error: None,
            last_transition: "created".to_string(),
        }
    }
}

/// `%ProgramData%\AnixOps\NetworkCore` ([`WINDOWS_MANAGED_PRODUCT_DIRECTORY`]),
/// built from its components so it lies under the managed root on every
/// platform the crate builds for.
pub fn windows_managed_data_directory() -> PathBuf {
    windows_managed_root_directory().join("NetworkCore")
}

pub fn windows_managed_config_path() -> PathBuf {
    windows_managed_data_directory().join(WINDOWS_MANAGED_CONFIG_FILE_NAME)
}

pub fn windows_managed_state_path() -> PathBuf {
    windows_managed_data_directory().join(WINDOWS_MANAGED_STATE_FILE_NAME)
}

pub fn windows_managed_log_directory() -> PathBuf {
    windows_managed_data_directory().join(WINDOWS_MANAGED_LOG_DIRECTORY)
}

pub fn windows_managed_log_path(component: &str) -> PathBuf {
    windows_managed_log_directory().join(format!("{component}.log"))
}

/// Append a human-readable diagnostic line without making logging a prerequisite for runtime work.
pub fn append_managed_log(component: &str, message: &str) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    // The log folder is secured once per process, not on every line.
    static LOG_DIRECTORY_SECURED: AtomicBool = AtomicBool::new(false);
    let path = windows_managed_log_path(component);
    if let Some(parent) = path.parent() {
        if !LOG_DIRECTORY_SECURED.load(Ordering::Acquire) {
            ensure_managed_directory(parent)?;
            LOG_DIRECTORY_SECURED.store(true, Ordering::Release);
        }
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[unix_ms={timestamp}] {message}")
}

pub fn read_managed_config(path: &Path) -> DomainResult<WindowsManagedConfig> {
    let bytes = read_managed_file(path)
        .map_err(|_| config_io_error("managed configuration could not be read"))?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| config_error("managed configuration is not valid JSON"))?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(WINDOWS_MANAGED_CONFIG_LEGACY_SCHEMA_VERSION as u64)
    {
        let object = value
            .as_object_mut()
            .ok_or_else(|| config_error("managed configuration schema 1 must be a JSON object"))?;
        object.insert(
            "schema_version".to_string(),
            serde_json::Value::from(WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION),
        );
        object.insert(
            "system_proxy_owner".to_string(),
            serde_json::Value::from("service"),
        );
    }
    let config: WindowsManagedConfig = serde_json::from_value(value)
        .map_err(|_| config_error("managed configuration is not valid JSON"))?;
    config.validate()?;
    if is_within_managed_root(path) {
        validate_managed_file_references(&config)?;
    }
    Ok(config)
}

/// The managed configuration names files the elevated engine then loads
/// (the engine envelope, the HTTPS decryption root and its key). Read from
/// the managed folder, it may only name files inside that folder, so an
/// edited configuration cannot point the engine at a file another account
/// controls.
pub fn validate_managed_file_references(config: &WindowsManagedConfig) -> DomainResult<()> {
    let mut paths: Vec<&Path> = Vec::new();
    if let Some(embedded) = config.embedded.as_ref().filter(|embedded| embedded.enabled) {
        paths.push(&embedded.envelope_path);
    }
    if let Some(native_mitm) = config.native_mitm.as_ref().filter(|mitm| mitm.enabled) {
        paths.push(&native_mitm.ca_certificate_path);
        paths.push(&native_mitm.ca_private_key_path);
    }
    if paths.iter().all(|path| is_within_managed_root(path)) {
        Ok(())
    } else {
        Err(config_error(
            "managed configuration names a file outside the managed data directory",
        ))
    }
}

pub fn write_managed_config(path: &Path, config: &WindowsManagedConfig) -> DomainResult<()> {
    config.validate()?;
    if is_within_managed_root(path) {
        validate_managed_file_references(config)?;
    }
    write_json_atomic(path, config, WINDOWS_MANAGED_CONFIG_IO_CODE)
}

pub fn read_managed_state(path: &Path) -> DomainResult<WindowsManagedState> {
    let bytes =
        read_managed_file(path).map_err(|_| state_io_error("managed state could not be read"))?;
    let state: WindowsManagedState = serde_json::from_slice(&bytes)
        .map_err(|_| state_io_error("managed state is not valid JSON"))?;
    if state.schema_version != WINDOWS_MANAGED_STATE_SCHEMA_VERSION {
        return Err(state_io_error("unsupported managed state schema version"));
    }
    Ok(state)
}

pub fn write_managed_state(path: &Path, state: &WindowsManagedState) -> DomainResult<()> {
    if state.schema_version != WINDOWS_MANAGED_STATE_SCHEMA_VERSION {
        return Err(state_io_error("unsupported managed state schema version"));
    }
    write_json_atomic(path, state, WINDOWS_MANAGED_STATE_IO_CODE)
}

/// Atomically replace a service-owned text artifact such as an engine
/// configuration or its rollback snapshot.
pub fn write_managed_text_atomic(path: &Path, content: &str) -> DomainResult<()> {
    write_bytes_atomic(path, content.as_bytes(), WINDOWS_MANAGED_CONFIG_IO_CODE)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, code: &str) -> DomainResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| DomainError::new(code, "managed JSON could not be serialized"))?;
    write_bytes_atomic(path, &bytes, code)
}

/// Written through [`write_managed_file_atomic`]: a new file with a random
/// name, created exclusively with the protected access list in a protected
/// folder, then moved over `path`. A fixed temporary name (as before 1.0)
/// let a standard user pre-create it and own the committed file.
fn write_bytes_atomic(path: &Path, bytes: &[u8], code: &str) -> DomainResult<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {}
        _ => return Err(DomainError::new(code, "managed path has no parent")),
    }
    write_managed_file_atomic(path, bytes).map_err(|error| {
        DomainError::new(code, format!("managed file could not be written: {error}"))
    })
}

fn config_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_CONFIG_INVALID_CODE, message)
}

fn config_io_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_CONFIG_IO_CODE, message)
}

fn state_io_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_STATE_IO_CODE, message)
}
