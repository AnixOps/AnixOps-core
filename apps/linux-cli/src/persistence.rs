//! Files the CLI keeps on disk: the subscription catalog, refresh status,
//! node selection and the managed session's records.

use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandSubscriptionCatalogStore;

impl CommandSubscriptionCatalogStore {
    pub const fn new() -> Self {
        Self
    }

    pub fn add_source(
        &self,
        request: &SubscriptionCatalogAddRequest,
    ) -> DomainResult<SubscriptionCatalogAddReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source.id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }
        let source_location = request.source.location.trim();
        if source_location.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE,
                "subscription catalog source location cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        if catalog
            .sources
            .iter()
            .any(|source| source.id.trim() == source_id)
        {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_DUPLICATE_SOURCE_ID_CODE,
                format!("subscription catalog source id already exists: {source_id}"),
            ));
        }

        catalog.sources.push(SubscriptionCatalogSourceFile {
            id: source_id.to_string(),
            location: source_location.to_string(),
            refresh_location: None,
        });
        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogAddReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
            location_kind: subscription_catalog_location_kind(source_location).to_string(),
            location_redacted: true,
        })
    }

    pub fn list_sources(
        &self,
        request: &SubscriptionCatalogListRequest,
    ) -> DomainResult<SubscriptionCatalogListReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
        let sources = catalog
            .sources
            .iter()
            .map(|source| SubscriptionCatalogListEntry {
                source_id: source.id.trim().to_string(),
                location_kind: subscription_catalog_location_kind(source.location.trim())
                    .to_string(),
                location_redacted: true,
            })
            .collect::<Vec<_>>();

        Ok(SubscriptionCatalogListReport {
            catalog_path,
            source_count: sources.len(),
            sources,
        })
    }

    pub fn select_source(
        &self,
        request: &SubscriptionCatalogSelectRequest,
    ) -> DomainResult<SubscriptionCatalogSelectReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }

        let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
        let source = catalog
            .sources
            .iter()
            .find(|source| source.id.trim() == source_id)
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;

        Ok(SubscriptionCatalogSelectReport {
            catalog_path,
            source_id: source.id.trim().to_string(),
            location_kind: subscription_catalog_location_kind(source.location.trim()).to_string(),
            location_redacted: true,
        })
    }

    pub fn update_source(
        &self,
        request: &SubscriptionCatalogUpdateRequest,
    ) -> DomainResult<SubscriptionCatalogUpdateReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }
        let location = request.location.trim();
        if location.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE,
                "subscription catalog source location cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        let source = catalog
            .sources
            .iter_mut()
            .find(|source| source.id.trim() == source_id)
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;
        source.location = location.to_string();

        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogUpdateReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
            location_kind: subscription_catalog_location_kind(location).to_string(),
            location_redacted: true,
            validated_node_count: 0,
            added_node_count: 0,
            removed_node_count: 0,
            changed_node_count: 0,
        })
    }

    pub fn update_source_with_fetcher<F>(
        &self,
        request: &SubscriptionCatalogUpdateRequest,
        fetcher: &F,
    ) -> DomainResult<SubscriptionCatalogUpdateReport>
    where
        F: RemoteSubscriptionFetcher,
    {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let source_id = request.source_id.trim();
        let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
        let previous_location = catalog
            .sources
            .iter()
            .find(|source| source.id.trim() == source_id)
            .map(|source| source.location.trim().to_string())
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;

        let previous_nodes =
            parse_subscription_catalog_update_nodes(source_id, &previous_location, fetcher)?;
        let content = read_subscription_catalog_update_content(&request.location, fetcher)?;
        let subscription = CoreSubscriptionService::new();
        let document = subscription
            .parse(&RawSubscription {
                source_id: source_id.to_string(),
                content,
            })
            .map_err(|error| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
                    format!(
                        "subscription update candidate could not be parsed: {}",
                        error.code
                    ),
                )
            })?;
        let catalog = subscription.normalize(&document).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
                format!(
                    "subscription update candidate could not be normalized: {}",
                    error.code
                ),
            )
        })?;
        let current_nodes = subscription_node_index(&catalog.nodes);
        let previous_nodes = subscription_node_index(&previous_nodes);
        let added_node_count = current_nodes
            .keys()
            .filter(|id| !previous_nodes.contains_key(*id))
            .count();
        let removed_node_count = previous_nodes
            .keys()
            .filter(|id| !current_nodes.contains_key(*id))
            .count();
        let changed_node_count = current_nodes
            .iter()
            .filter(|(id, fingerprint)| {
                previous_nodes
                    .get(*id)
                    .is_some_and(|previous| previous != *fingerprint)
            })
            .count();
        let validated_node_count = current_nodes.len();
        let mut report = self.update_source(request)?;
        report.validated_node_count = validated_node_count;
        report.added_node_count = added_node_count;
        report.removed_node_count = removed_node_count;
        report.changed_node_count = changed_node_count;
        Ok(report)
    }

    pub fn rollback_catalog(
        &self,
        request: &SubscriptionCatalogRollbackRequest,
    ) -> DomainResult<SubscriptionCatalogRollbackReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }

        let (snapshot, snapshot_contents) =
            read_required_subscription_catalog_snapshot_file(&snapshot_path)?;
        write_replace_file(
            &catalog_path,
            snapshot_contents.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogRollbackReport {
            catalog_path,
            snapshot_path,
            source_count: snapshot.sources.len(),
            snapshot_retained: true,
        })
    }

    pub fn refresh_http_source_with_fetcher<F>(
        &self,
        request: &SubscriptionRefreshStartRequest,
        fetcher: &F,
    ) -> DomainResult<SubscriptionRefreshStatusReport>
    where
        F: RemoteSubscriptionFetcher,
    {
        if !request.confirmed {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_REFRESH_AUTHORIZATION_REQUIRED_CODE,
                "subscription refresh requires explicit --confirm",
            ));
        }
        if request.interval_seconds < SUBSCRIPTION_REFRESH_MIN_INTERVAL_SECONDS {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_REFRESH_INTERVAL_TOO_SHORT_CODE,
                "subscription refresh interval is below the fixed minimum",
            ));
        }
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let status_path = required_subscription_catalog_path(
            &request.status_path,
            CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE,
            "subscription refresh status path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription refresh snapshot path cannot be empty",
        )?;
        let source_id = request.source_id.trim();
        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        let source = catalog
            .sources
            .iter_mut()
            .find(|source| source.id.trim() == source_id)
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;
        let refresh_location = source
            .refresh_location
            .as_deref()
            .unwrap_or(source.location.as_str())
            .trim()
            .to_string();
        if !(refresh_location.starts_with("http://") || refresh_location.starts_with("https://")) {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_REFRESH_SOURCE_UNSUPPORTED_CODE,
                "background refresh accepts only a saved HTTP(S) source",
            ));
        }
        let _refresh_lock = SubscriptionRefreshLock::acquire(&status_path, source_id)?;
        let previous_location = source.location.clone();
        let attempted_at = subscription_refresh_timestamp();
        let candidate = fetcher
            .fetch_subscription(&refresh_location)
            .and_then(|content| {
                let previous_nodes = parse_subscription_catalog_update_nodes(
                    source_id,
                    &previous_location,
                    fetcher,
                )?;
                let service = CoreSubscriptionService::new();
                let document = service
                    .parse(&RawSubscription {
                        source_id: source_id.to_string(),
                        content: content.clone(),
                    })
                    .map_err(|error| {
                        DomainError::new(
                            CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
                            format!(
                                "subscription refresh candidate could not be parsed: {}",
                                error.code
                            ),
                        )
                    })?;
                let candidate_catalog = service.normalize(&document).map_err(|error| {
                    DomainError::new(
                        CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
                        format!(
                            "subscription refresh candidate could not be normalized: {}",
                            error.code
                        ),
                    )
                })?;
                Ok((content, candidate_catalog.nodes, previous_nodes))
            });
        let next_attempt = subscription_refresh_next_timestamp(request.interval_seconds);
        match candidate {
            Ok((content, candidate_nodes, previous_nodes)) => {
                source.location = format!("inline:{content}");
                source.refresh_location = Some(refresh_location);
                let previous_node_index = subscription_node_index(&previous_nodes);
                let candidate_node_index = subscription_node_index(&candidate_nodes);
                let added_node_count = candidate_node_index
                    .keys()
                    .filter(|id| !previous_node_index.contains_key(*id))
                    .count();
                let removed_node_count = previous_node_index
                    .keys()
                    .filter(|id| !candidate_node_index.contains_key(*id))
                    .count();
                let changed_node_count = candidate_node_index
                    .iter()
                    .filter(|(id, value)| {
                        previous_node_index
                            .get(*id)
                            .is_some_and(|previous| previous != *value)
                    })
                    .count();
                let snapshot_json =
                    serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
                        DomainError::new(
                            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                            format!("failed to render subscription refresh snapshot: {error}"),
                        )
                    })?;
                let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
                    DomainError::new(
                        CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                        format!("failed to render refreshed subscription catalog: {error}"),
                    )
                })?;
                write_replace_file(
                    &snapshot_path,
                    snapshot_json.as_bytes(),
                    CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                    "subscription refresh snapshot",
                )?;
                write_replace_file(
                    &catalog_path,
                    catalog_json.as_bytes(),
                    CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                    "refreshed subscription catalog",
                )?;
                let status = SubscriptionRefreshStatusFile {
                    schema_version: 1,
                    source_id: source_id.to_string(),
                    enabled: true,
                    interval_seconds: request.interval_seconds,
                    last_attempt: attempted_at.clone(),
                    last_success: Some(attempted_at.clone()),
                    next_attempt: next_attempt.clone(),
                    result: "success".to_string(),
                    error_redacted: false,
                    error_code: None,
                    added_node_count,
                    removed_node_count,
                    changed_node_count,
                };
                write_subscription_refresh_status_file(&status_path, &status)?;
                Ok(subscription_refresh_report(status_path, status))
            }
            Err(error) => {
                let status = SubscriptionRefreshStatusFile {
                    schema_version: 1,
                    source_id: source_id.to_string(),
                    enabled: true,
                    interval_seconds: request.interval_seconds,
                    last_attempt: attempted_at,
                    last_success: read_subscription_refresh_status_file(&status_path)
                        .ok()
                        .and_then(|status| status.last_success),
                    next_attempt,
                    result: "failed".to_string(),
                    error_redacted: true,
                    error_code: Some(error.code.clone()),
                    added_node_count: 0,
                    removed_node_count: 0,
                    changed_node_count: 0,
                };
                write_subscription_refresh_status_file(&status_path, &status)?;
                Err(DomainError::new(error.code, "subscription refresh failed; previous catalog and runtime selection were retained"))
            }
        }
    }

    pub fn read_refresh_status(
        &self,
        status_path: &str,
    ) -> DomainResult<SubscriptionRefreshStatusReport> {
        let status_path = required_subscription_catalog_path(
            status_path,
            CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE,
            "subscription refresh status path cannot be empty",
        )?;
        let status = read_subscription_refresh_status_file(&status_path)?;
        Ok(subscription_refresh_report(status_path, status))
    }

    pub fn stop_refresh(
        &self,
        status_path: &str,
        source_id: &str,
        confirmed: bool,
    ) -> DomainResult<SubscriptionRefreshStatusReport> {
        if !confirmed {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_REFRESH_AUTHORIZATION_REQUIRED_CODE,
                "subscription refresh stop requires explicit --confirm",
            ));
        }
        let status_path = required_subscription_catalog_path(
            status_path,
            CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE,
            "subscription refresh status path cannot be empty",
        )?;
        let mut status = match read_subscription_refresh_status_file(&status_path) {
            Ok(status) => status,
            Err(error)
                if error.code == CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE
                    && !std::path::Path::new(&status_path).exists() =>
            {
                SubscriptionRefreshStatusFile {
                    schema_version: 1,
                    source_id: source_id.trim().to_string(),
                    enabled: false,
                    interval_seconds: SUBSCRIPTION_REFRESH_MIN_INTERVAL_SECONDS,
                    last_attempt: "none".to_string(),
                    last_success: None,
                    next_attempt: "none".to_string(),
                    result: "stopped".to_string(),
                    error_redacted: false,
                    error_code: None,
                    added_node_count: 0,
                    removed_node_count: 0,
                    changed_node_count: 0,
                }
            }
            Err(error) => return Err(error),
        };
        if status.source_id != source_id.trim() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                "subscription refresh source id does not match the explicit status record",
            ));
        }
        status.enabled = false;
        status.result = "stopped".to_string();
        status.next_attempt = "none".to_string();
        write_subscription_refresh_status_file(&status_path, &status)?;
        let _ = std::fs::remove_file(SubscriptionRefreshLock::path_for(&status_path, source_id));
        Ok(subscription_refresh_report(status_path, status))
    }

    pub fn remove_source(
        &self,
        request: &SubscriptionCatalogRemoveRequest,
    ) -> DomainResult<SubscriptionCatalogRemoveReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        let source_exists = catalog
            .sources
            .iter()
            .any(|source| source.id.trim() == source_id);
        if !source_exists {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                format!("subscription catalog source id was not found: {source_id}"),
            ));
        }
        catalog
            .sources
            .retain(|source| source.id.trim() != source_id);

        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogRemoveReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubscriptionCatalogFile {
    pub(crate) schema_version: u32,
    pub(crate) sources: Vec<SubscriptionCatalogSourceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubscriptionCatalogSourceFile {
    pub(crate) id: String,
    pub(crate) location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubscriptionRefreshStatusFile {
    pub(crate) schema_version: u32,
    pub(crate) source_id: String,
    pub(crate) enabled: bool,
    pub(crate) interval_seconds: u64,
    pub(crate) last_attempt: String,
    pub(crate) last_success: Option<String>,
    pub(crate) next_attempt: String,
    pub(crate) result: String,
    pub(crate) error_redacted: bool,
    pub(crate) error_code: Option<String>,
    pub(crate) added_node_count: usize,
    pub(crate) removed_node_count: usize,
    pub(crate) changed_node_count: usize,
}

pub(crate) struct SubscriptionRefreshLock {
    pub(crate) path: std::path::PathBuf,
}

impl SubscriptionRefreshLock {
    pub(crate) fn path_for(status_path: &str, source_id: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{status_path}.{source_id}.refresh.lock"))
    }

    pub(crate) fn acquire(status_path: &str, source_id: &str) -> DomainResult<Self> {
        let path = Self::path_for(status_path, source_id);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| {
                DomainError::new(
                    CLI_SUBSCRIPTION_REFRESH_ALREADY_ACTIVE_CODE,
                    "a refresh is already active for this source",
                )
            })?;
        Ok(Self { path })
    }
}

impl Drop for SubscriptionRefreshLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) const NODE_SELECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeSelectionFile {
    pub(crate) schema_version: u32,
    pub(crate) node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ManagedForegroundSessionStatusFile {
    pub(crate) schema_version: u32,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ManagedForegroundSessionEventFile {
    pub(crate) schema_version: u32,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) event_id: String,
    pub(crate) event_kind: String,
    pub(crate) state: String,
    pub(crate) recorded_at: String,
}

pub(crate) fn required_subscription_catalog_path(
    path: &str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(code, message));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_status_path(path: &str) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE,
            "managed foreground status path cannot be empty",
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_status_snapshot_path(path: &str) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_PATH_MISSING_CODE,
            "managed foreground status snapshot path cannot be empty",
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_event_path(path: &str) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_PATH_MISSING_CODE,
            "managed foreground event path cannot be empty",
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_event_directory_path(path: &str) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_DIRECTORY_MISSING_CODE,
            "managed foreground event directory cannot be empty",
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_log_path(path: &str) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_LOG_PATH_MISSING_CODE,
            "managed foreground log path cannot be empty",
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn required_managed_foreground_log_tail_limit(limit: usize) -> DomainResult<usize> {
    if !(1..=MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT).contains(&limit) {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_LOG_QUERY_INVALID_CODE,
            format!(
                "managed foreground log tail limit must be between 1 and {MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT}"
            ),
        ));
    }
    Ok(limit)
}

pub(crate) fn optional_managed_foreground_event_history_session_id(
    session_id: Option<&str>,
) -> DomainResult<Option<String>> {
    session_id
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return Err(DomainError::new(
                    CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE,
                    "managed foreground event history session filter cannot be empty",
                ));
            }
            Ok(value.to_string())
        })
        .transpose()
}

pub(crate) fn optional_managed_foreground_event_history_kind(
    event_kind: Option<&str>,
) -> DomainResult<Option<String>> {
    event_kind
        .map(|value| {
            let value = value.trim();
            if !matches!(
                value,
                "session_started" | "status_transition" | "session_stopped" | "session_failed"
            ) {
                return Err(DomainError::new(
                    CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE,
                    "managed foreground event history kind filter is unsupported",
                ));
            }
            Ok(value.to_string())
        })
        .transpose()
}

pub(crate) fn optional_managed_foreground_event_history_state(
    state: Option<&str>,
) -> DomainResult<Option<String>> {
    state
        .map(|value| {
            required_managed_foreground_status_state(
                value,
                CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE,
                "managed foreground event history state filter is unsupported",
            )
        })
        .transpose()
}

pub(crate) fn required_managed_foreground_event_history_limit(limit: usize) -> DomainResult<usize> {
    if !(1..=MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT).contains(&limit) {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE,
            format!(
                "managed foreground event history limit must be between 1 and {MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT}"
            ),
        ));
    }
    Ok(limit)
}

pub(crate) fn managed_foreground_event_history_paths(
    event_directory: &str,
) -> DomainResult<Vec<std::path::PathBuf>> {
    let entries = std::fs::read_dir(event_directory).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
            format!("failed to read managed foreground event directory {event_directory}: {error}"),
        )
    })?;
    let mut event_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
                format!(
                    "failed to enumerate managed foreground event directory {event_directory}: {error}"
                ),
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
                format!(
                    "failed to inspect managed foreground event directory {event_directory}: {error}"
                ),
            )
        })?;
        let path = entry.path();
        if !file_type.is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        if event_paths.len() == MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORDS {
            return Err(DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_HISTORY_LIMIT_EXCEEDED_CODE,
                format!(
                    "managed foreground event directory {event_directory} exceeds the {} record history limit",
                    MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORDS
                ),
            ));
        }
        event_paths.push(path);
    }
    event_paths.sort();
    Ok(event_paths)
}

pub(crate) fn read_managed_foreground_session_status_file(
    path: &str,
) -> DomainResult<(ManagedForegroundSessionStatusFile, String)> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_READ_FAILED_CODE,
            format!("failed to read managed foreground status record {path}: {error}"),
        )
    })?;
    let record =
        serde_json::from_str::<ManagedForegroundSessionStatusFile>(&contents).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_READ_FAILED_CODE,
                format!("failed to parse managed foreground status record {path}: {error}"),
            )
        })?;
    validate_managed_foreground_session_status_file(&record)?;
    Ok((record, contents))
}

pub(crate) fn read_managed_foreground_session_status_snapshot_file(
    path: &str,
) -> DomainResult<(ManagedForegroundSessionStatusFile, String)> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_READ_FAILED_CODE,
            format!("failed to read managed foreground status snapshot {path}: {error}"),
        )
    })?;
    let record =
        serde_json::from_str::<ManagedForegroundSessionStatusFile>(&contents).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_READ_FAILED_CODE,
                format!("failed to parse managed foreground status snapshot {path}: {error}"),
            )
        })?;
    validate_managed_foreground_session_status_file(&record)?;
    Ok((record, contents))
}

pub(crate) fn read_managed_foreground_session_event_file(
    path: &str,
) -> DomainResult<ManagedForegroundSessionEventFile> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
            format!("failed to read managed foreground event record {path}: {error}"),
        )
    })?;
    parse_managed_foreground_session_event_contents(path, &contents)
}

pub(crate) fn read_managed_foreground_session_event_history_file(
    path: &str,
) -> DomainResult<ManagedForegroundSessionEventFile> {
    let file = std::fs::File::open(path).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
            format!("failed to read managed foreground event record {path}: {error}"),
        )
    })?;
    let mut contents =
        Vec::with_capacity((MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORD_BYTES + 1) as usize);
    file.take(MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
                format!("failed to read managed foreground event record {path}: {error}"),
            )
        })?;
    if contents.len() as u64 > MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORD_BYTES {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_HISTORY_LIMIT_EXCEEDED_CODE,
            format!(
                "managed foreground event record {path} exceeds the {} byte history limit",
                MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORD_BYTES
            ),
        ));
    }
    let contents = String::from_utf8(contents).map_err(|error| {
        DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
            format!("failed to read managed foreground event record {path}: {error}"),
        )
    })?;
    parse_managed_foreground_session_event_contents(path, &contents)
}

pub(crate) fn parse_managed_foreground_session_event_contents(
    path: &str,
    contents: &str,
) -> DomainResult<ManagedForegroundSessionEventFile> {
    let record =
        serde_json::from_str::<ManagedForegroundSessionEventFile>(contents).map_err(|error| {
            DomainError::new(
                CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE,
                format!("failed to parse managed foreground event record {path}: {error}"),
            )
        })?;
    validate_managed_foreground_session_event_file(&record)?;
    Ok(record)
}

pub(crate) fn required_managed_foreground_status_state(
    state: &str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    let state = state.trim();
    if !matches!(state, "starting" | "running" | "stopped" | "failed") {
        return Err(DomainError::new(code, message));
    }
    Ok(state.to_string())
}

pub(crate) fn is_managed_foreground_status_transition_allowed(
    previous_state: &str,
    next_state: &str,
) -> bool {
    matches!(
        (previous_state, next_state),
        ("starting", "running" | "failed") | ("running", "stopped" | "failed")
    )
}

pub(crate) fn validate_managed_foreground_session_status_file(
    record: &ManagedForegroundSessionStatusFile,
) -> DomainResult<()> {
    if record.schema_version != MANAGED_FOREGROUND_SESSION_STATUS_SCHEMA_VERSION {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_SCHEMA_UNSUPPORTED_CODE,
            "managed foreground status schema version is unsupported",
        ));
    }
    if record.session_id.trim().is_empty() || record.engine_id.trim().is_empty() {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE,
            "managed foreground status record contains an empty session or engine id",
        ));
    }
    required_managed_foreground_status_state(
        &record.state,
        CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE,
        "managed foreground status record contains an unsupported state",
    )?;
    Ok(())
}

pub(crate) fn validate_managed_foreground_session_event_file(
    record: &ManagedForegroundSessionEventFile,
) -> DomainResult<()> {
    if record.schema_version != MANAGED_FOREGROUND_SESSION_EVENT_SCHEMA_VERSION {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_SCHEMA_UNSUPPORTED_CODE,
            "managed foreground event schema version is unsupported",
        ));
    }
    if record.session_id.trim().is_empty()
        || record.engine_id.trim().is_empty()
        || record.event_id.trim().is_empty()
        || record.recorded_at.trim().is_empty()
    {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE,
            "managed foreground event record contains an empty required identifier or timestamp",
        ));
    }
    if !matches!(
        record.event_kind.trim(),
        "session_started" | "status_transition" | "session_stopped" | "session_failed"
    ) {
        return Err(DomainError::new(
            CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE,
            "managed foreground event record contains an unsupported event kind",
        ));
    }
    required_managed_foreground_status_state(
        &record.state,
        CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE,
        "managed foreground event record contains an unsupported state",
    )?;
    Ok(())
}

pub(crate) fn read_subscription_catalog_file(
    path: &str,
) -> DomainResult<(SubscriptionCatalogFile, SubscriptionCatalogFile)> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let empty = SubscriptionCatalogFile {
                schema_version: SUBSCRIPTION_CATALOG_SCHEMA_VERSION,
                sources: Vec::new(),
            };
            return Ok((empty.clone(), empty));
        }
        Err(error) => {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE,
                format!("failed to read subscription catalog {path}: {error}"),
            ));
        }
    };
    let catalog = serde_json::from_str::<SubscriptionCatalogFile>(&contents).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE,
            format!("failed to parse subscription catalog {path}: {error}"),
        )
    })?;
    let catalog = validate_subscription_catalog_file(catalog)?;
    Ok((catalog.clone(), catalog))
}

pub(crate) fn read_subscription_catalog_source_location(
    catalog_path: &str,
    source_id: &str,
) -> DomainResult<String> {
    let catalog_path = required_subscription_catalog_path(
        catalog_path,
        CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
        "subscription catalog path cannot be empty",
    )?;
    let source_id = source_id.trim();
    if source_id.is_empty() {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
            "subscription catalog source id cannot be empty",
        ));
    }
    let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
    let location = catalog
        .sources
        .iter()
        .find(|source| source.id.trim() == source_id)
        .map(|source| source.location.trim())
        .ok_or_else(|| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                format!("subscription catalog source id was not found: {source_id}"),
            )
        })?;

    Ok(location
        .strip_prefix("inline:")
        .unwrap_or(location)
        .to_string())
}

pub(crate) fn read_required_subscription_catalog_snapshot_file(
    path: &str,
) -> DomainResult<(SubscriptionCatalogFile, String)> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE,
            format!("failed to read subscription catalog rollback snapshot {path}: {error}"),
        )
    })?;
    let catalog = serde_json::from_str::<SubscriptionCatalogFile>(&contents).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE,
            format!("failed to parse subscription catalog rollback snapshot {path}: {error}"),
        )
    })?;
    Ok((validate_subscription_catalog_file(catalog)?, contents))
}

pub(crate) fn validate_subscription_catalog_file(
    catalog: SubscriptionCatalogFile,
) -> DomainResult<SubscriptionCatalogFile> {
    if catalog.schema_version != SUBSCRIPTION_CATALOG_SCHEMA_VERSION {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SCHEMA_UNSUPPORTED_CODE,
            "subscription catalog schema version is unsupported",
        ));
    }
    if catalog
        .sources
        .iter()
        .any(|source| source.id.trim().is_empty() || source.location.trim().is_empty())
    {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SOURCE_INVALID_CODE,
            "subscription catalog contains an empty source id or location",
        ));
    }
    Ok(catalog)
}

pub(crate) fn subscription_catalog_location_kind(location: &str) -> &'static str {
    if location.starts_with("inline:") {
        "inline"
    } else if location.starts_with("http://") || location.starts_with("https://") {
        "remote"
    } else if location.starts_with("file:") {
        "file"
    } else {
        "other"
    }
}

pub(crate) fn subscription_refresh_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

pub(crate) fn subscription_refresh_next_timestamp(interval_seconds: u64) -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(interval_seconds)
        .to_string()
}

pub(crate) fn read_subscription_refresh_status_file(
    path: &str,
) -> DomainResult<SubscriptionRefreshStatusFile> {
    let contents = std::fs::read_to_string(path).map_err(|_| {
        DomainError::new(
            CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE,
            "subscription refresh status could not be read",
        )
    })?;
    let status =
        serde_json::from_str::<SubscriptionRefreshStatusFile>(&contents).map_err(|_| {
            DomainError::new(
                CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE,
                "subscription refresh status is invalid",
            )
        })?;
    if status.schema_version != 1 || status.source_id.trim().is_empty() {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE,
            "subscription refresh status schema is unsupported",
        ));
    }
    Ok(status)
}

pub(crate) fn write_subscription_refresh_status_file(
    path: &str,
    status: &SubscriptionRefreshStatusFile,
) -> DomainResult<()> {
    let json = serde_json::to_string_pretty(status).map_err(|_| {
        DomainError::new(
            CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE,
            "subscription refresh status could not be rendered",
        )
    })?;
    write_replace_file(
        path,
        json.as_bytes(),
        CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE,
        "subscription refresh status",
    )
}

pub(crate) fn subscription_refresh_report(
    status_path: String,
    status: SubscriptionRefreshStatusFile,
) -> SubscriptionRefreshStatusReport {
    SubscriptionRefreshStatusReport {
        status_path,
        source_id: status.source_id,
        enabled: status.enabled,
        last_attempt: status.last_attempt,
        last_success: status.last_success,
        next_attempt: status.next_attempt,
        result: status.result,
        error_redacted: status.error_redacted,
        error_code: status.error_code,
        added_node_count: status.added_node_count,
        removed_node_count: status.removed_node_count,
        changed_node_count: status.changed_node_count,
    }
}
