//! Builds the native proxy engine service: MITM plugins, TLS MITM key
//! material read from disk, and the local script runtime.

use super::*;

/// The native engine with the user's own MITM plugin as its HTTP MITM hook.
pub fn native_proxy_engine_service_with_mitm_plugin(
    package: &PluginPackage,
) -> DomainResult<engine_native::NativeProxyEngineService> {
    native_proxy_engine_service_with_mitm_plugin_and_runtime(Some(package), None, None)
}

/// The native engine with an optional user MITM plugin. NetworkCore ships no
/// plugin (docs/no-presets.md): without one the engine has no HTTP MITM hook,
/// and HTTPS MITM or the script runtime, which only act on a plugin's rules,
/// are refused.
pub fn native_proxy_engine_service_with_mitm_plugin_and_runtime(
    package: Option<&PluginPackage>,
    tls_mitm_ca_material: Option<engine_native::NativeTlsMitmCaMaterial>,
    script_executor: Option<engine_native::NativeHttpScriptExecutor>,
) -> DomainResult<engine_native::NativeProxyEngineService> {
    let Some(package) = package else {
        if tls_mitm_ca_material.is_some() || script_executor.is_some() {
            return Err(DomainError::new(
                CLI_START_MITM_PLUGIN_REQUIRED_CODE,
                "HTTPS MITM and the script runtime need your own MITM plugin: pass --mitm-plugin <path>; NetworkCore ships none",
            ));
        }
        return Ok(engine_native::NativeProxyEngineService::new());
    };
    let service = AnixOpsMitmPluginService::new();
    let instance = service.load(
        package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;
    let hook = engine_native::NativeHttpMitmPluginHook::new(instance, Arc::new(service));
    let hook = match script_executor {
        Some(engine_native::NativeHttpScriptExecutor::Node(executor)) => {
            hook.with_node_script_executor(executor)
        }
        Some(engine_native::NativeHttpScriptExecutor::QuickJs(executor)) => {
            hook.with_quickjs_script_executor(executor)
        }
        None => hook,
    };

    let service = engine_native::NativeProxyEngineService::new().with_http_mitm_hook(hook);
    Ok(match tls_mitm_ca_material {
        Some(material) => service.with_tls_mitm_ca_material(material),
        None => service,
    })
}

/// The user's MITM plugin file as a package.
pub fn read_user_mitm_plugin(path: &str) -> DomainResult<PluginPackage> {
    let source = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_MITM_PLUGIN_READ_FAILED_CODE,
            format!("MITM plugin {path} could not be read: {error}"),
        )
    })?;
    Ok(user_plugin_package(source))
}

pub fn native_proxy_engine_service_with_mitm_plugin_and_tls_mitm_files(
    plugin_path: Option<&str>,
    certificate_path: Option<&str>,
    private_key_path: Option<&str>,
    enable_https_mitm: bool,
    confirm: bool,
) -> DomainResult<engine_native::NativeProxyEngineService> {
    native_proxy_engine_service_with_mitm_plugin_and_runtime_files(
        LinuxNativeMitmRuntimeFileConfig {
            plugin_path,
            certificate_path,
            private_key_path,
            enable_https_mitm,
            enable_script_runtime: false,
            script_runner_path: None,
            node_binary: None,
            script_maps: &[],
            script_store_path: None,
            confirm,
        },
    )
}

pub fn native_proxy_engine_service_with_mitm_plugin_and_runtime_files(
    runtime_config: LinuxNativeMitmRuntimeFileConfig<'_>,
) -> DomainResult<engine_native::NativeProxyEngineService> {
    let LinuxNativeMitmRuntimeFileConfig {
        plugin_path,
        certificate_path,
        private_key_path,
        enable_https_mitm,
        enable_script_runtime,
        script_runner_path,
        node_binary,
        script_maps,
        script_store_path,
        confirm,
    } = runtime_config;
    let tls_mitm_ca_material = if enable_https_mitm {
        if !confirm {
            return Err(DomainError::new(
                CLI_START_TLS_MITM_AUTHORIZATION_REQUIRED_CODE,
                "live HTTPS MITM start requires explicit --confirm authorization",
            ));
        }
        let (Some(certificate_path), Some(private_key_path)) = (certificate_path, private_key_path)
        else {
            return Err(DomainError::new(
                CLI_START_TLS_MITM_MATERIAL_REQUIRED_CODE,
                "live HTTPS MITM start requires both --mitm-ca-cert and --mitm-ca-key",
            ));
        };
        let certificate_pem = std::fs::read_to_string(certificate_path).map_err(|_| {
            DomainError::new(
                CLI_START_TLS_MITM_MATERIAL_READ_FAILED_CODE,
                "live HTTPS MITM CA certificate material could not be read",
            )
        })?;
        let private_key_pem = read_tls_mitm_private_key_file(private_key_path)?;
        if certificate_pem.trim().is_empty() || private_key_pem.trim().is_empty() {
            return Err(DomainError::new(
                CLI_START_TLS_MITM_MATERIAL_REQUIRED_CODE,
                "live HTTPS MITM CA certificate and private key material must be non-empty",
            ));
        }
        Some(engine_native::NativeTlsMitmCaMaterial::new(
            certificate_pem,
            private_key_pem,
        ))
    } else {
        if certificate_path.is_some() || private_key_path.is_some() {
            return Err(DomainError::new(
                CLI_START_TLS_MITM_AUTHORIZATION_REQUIRED_CODE,
                "CA material requires explicit --enable-https-mitm and --confirm authorization",
            ));
        }
        None
    };

    let script_executor = build_native_script_executor(
        enable_script_runtime,
        script_runner_path,
        node_binary,
        script_maps,
        script_store_path,
        confirm,
    )?;

    let package = plugin_path.map(read_user_mitm_plugin).transpose()?;
    native_proxy_engine_service_with_mitm_plugin_and_runtime(
        package.as_ref(),
        tls_mitm_ca_material,
        script_executor,
    )
}

#[cfg(target_os = "linux")]
pub(crate) const LINUX_O_NOFOLLOW: i32 = 0o400000;

#[cfg(target_os = "linux")]
pub(crate) fn read_tls_mitm_private_key_file(path: &str) -> DomainResult<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(path)
        .map_err(|_| private_key_protection_error())?;
    let metadata = file
        .metadata()
        .map_err(|_| private_key_protection_error())?;
    validate_tls_mitm_private_key_metadata(&metadata)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| private_key_read_error())?;
    Ok(contents)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn read_tls_mitm_private_key_file(path: &str) -> DomainResult<String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| private_key_protection_error())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(private_key_protection_error());
    }
    validate_tls_mitm_private_key_metadata(&metadata)?;
    std::fs::read_to_string(path).map_err(|_| private_key_read_error())
}

#[cfg(unix)]
pub(crate) fn validate_tls_mitm_private_key_metadata(
    metadata: &std::fs::Metadata,
) -> DomainResult<()> {
    if !metadata.file_type().is_file() {
        return Err(private_key_protection_error());
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(private_key_protection_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn read_tls_mitm_private_key_file(path: &str) -> DomainResult<String> {
    std::fs::read_to_string(path).map_err(|_| private_key_read_error())
}

#[cfg(unix)]
pub(crate) fn private_key_protection_error() -> DomainError {
    DomainError::new(
        CLI_START_TLS_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE,
        "live HTTPS MITM CA private key protection could not be verified",
    )
}

pub(crate) fn private_key_read_error() -> DomainError {
    DomainError::new(
        CLI_START_TLS_MITM_MATERIAL_READ_FAILED_CODE,
        "live HTTPS MITM CA private key material could not be read",
    )
}

/// Builds the `[Script]` executor. Without `--script-runner` scripts run in
/// the in-process QuickJS runtime, which has no file system, process, or
/// network access, so it may keep a persistent store. With `--script-runner`
/// they run in the sandboxed Node runner, which has no store permission.
pub(crate) fn build_native_script_executor(
    enable_script_runtime: bool,
    script_runner_path: Option<&str>,
    node_binary: Option<&str>,
    script_maps: &[String],
    script_store_path: Option<&str>,
    confirm: bool,
) -> DomainResult<Option<engine_native::NativeHttpScriptExecutor>> {
    if !enable_script_runtime {
        if script_runner_path.is_some()
            || node_binary.is_some()
            || !script_maps.is_empty()
            || script_store_path.is_some()
        {
            return Err(DomainError::new(
                CLI_START_SCRIPT_RUNTIME_AUTHORIZATION_REQUIRED_CODE,
                "script runtime configuration requires explicit --enable-script-runtime and --confirm authorization",
            ));
        }
        return Ok(None);
    }
    if !confirm {
        return Err(DomainError::new(
            CLI_START_SCRIPT_RUNTIME_AUTHORIZATION_REQUIRED_CODE,
            "script runtime start requires explicit --confirm authorization",
        ));
    }
    if script_maps.is_empty() {
        return Err(DomainError::new(
            CLI_START_SCRIPT_RUNTIME_CONFIG_REQUIRED_CODE,
            "script runtime start requires at least one --script-map",
        ));
    }
    if script_runner_path.is_some() && script_store_path.is_some() {
        return Err(DomainError::new(
            CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
            "sandboxed Node script runtime does not permit a persistent script store",
        ));
    }
    if script_runner_path.is_none() && node_binary.is_some() {
        return Err(DomainError::new(
            CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
            "--node-binary only applies to the Node runner selected with --script-runner",
        ));
    }

    let mut script_assets = BTreeMap::new();
    for script_map in script_maps {
        let Some((script_url, local_path)) = script_map.split_once('=') else {
            return Err(DomainError::new(
                CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
                "script runtime mappings must use script-url=local-file form",
            ));
        };
        let script_url = script_url.trim();
        let local_path = local_path.trim();
        if !(script_url.starts_with("https://") || script_url.starts_with("http://"))
            || local_path.is_empty()
            || script_assets
                .insert(
                    script_url.to_string(),
                    canonical_local_script_runtime_file(local_path)?,
                )
                .is_some()
        {
            return Err(DomainError::new(
                CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
                "script runtime mappings must use unique remote URLs and existing local files",
            ));
        }
    }

    let Some(script_runner_path) = script_runner_path else {
        let executor = engine_native::NativeQuickJsScriptExecutor::new(
            engine_native::NativeQuickJsScriptRuntimeConfig {
                script_assets,
                persistent_store_path: script_store_path.map(str::to_string),
                max_timeout_ms: 30_000,
                max_body_bytes: 1024 * 1024,
                memory_limit_bytes: 0,
            },
        )
        .map_err(|_| {
            DomainError::new(
                CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
                "QuickJS script runtime needs readable script files and a JSON object store file",
            )
        })?;
        return Ok(Some(engine_native::NativeHttpScriptExecutor::QuickJs(
            executor,
        )));
    };
    let script_runner_path = canonical_local_script_runtime_file(script_runner_path)?;

    Ok(Some(engine_native::NativeHttpScriptExecutor::Node(
        engine_native::NativeNodeScriptExecutor::new(
            engine_native::NativeNodeScriptRuntimeConfig {
                node_binary: node_binary.unwrap_or("node").to_string(),
                runner_path: script_runner_path,
                script_assets,
                persistent_store_path: None,
                sandbox: engine_native::NativeNodeScriptSandbox::LinuxNoNetwork,
                max_timeout_ms: 30_000,
                max_body_bytes: 64 * 1024,
            },
        ),
    )))
}

pub(crate) fn canonical_local_script_runtime_file(path: &str) -> DomainResult<String> {
    let path = std::path::Path::new(path);
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        DomainError::new(
            CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
            "configured script runtime path is not a readable local regular file",
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(DomainError::new(
            CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
            "configured script runtime path must be a local regular file without symbolic links",
        ));
    }
    std::fs::canonicalize(path)
        .map_err(|_| {
            DomainError::new(
                CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
                "configured script runtime path could not be resolved",
            )
        })?
        .into_os_string()
        .into_string()
        .map_err(|_| {
            DomainError::new(
                CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE,
                "configured script runtime path must be valid UTF-8",
            )
        })
}
