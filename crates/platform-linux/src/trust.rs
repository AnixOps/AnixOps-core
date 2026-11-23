//! Explicit Ubuntu-style CA trust-file mutation.
//!
//! The caller supplies both the trust-file and rollback snapshot paths. This
//! adapter never discovers a distribution default and refreshes the trust
//! database only after an explicitly confirmed, verified file write.

use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LINUX_TRUST_SCHEMA_VERSION: u32 = 1;
pub const LINUX_TRUST_INVALID_CODE: &str = "platform.linux.trust.invalid";
pub const LINUX_TRUST_CONFIRMATION_REQUIRED_CODE: &str =
    "platform.linux.trust.confirmation_required";
pub const LINUX_TRUST_WRITE_FAILED_CODE: &str = "platform.linux.trust.write_failed";
pub const LINUX_TRUST_REFRESH_FAILED_CODE: &str = "platform.linux.trust.refresh_failed";
pub const LINUX_TRUST_ROLLBACK_FAILED_CODE: &str = "platform.linux.trust.rollback_failed";
pub const LINUX_TRUST_CONFLICT_CODE: &str = "platform.linux.trust.external_change";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustApplyRequest {
    pub certificate_path: PathBuf,
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustApplyReport {
    pub certificate_path: PathBuf,
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub previous_exists: bool,
    pub verified: bool,
    pub refreshed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustRollbackRequest {
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustRollbackReport {
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub restored_previous_file: bool,
    pub snapshot_retained: bool,
    pub refreshed: bool,
}

pub trait LinuxTrustRefreshRunner {
    fn refresh(&self) -> DomainResult<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandLinuxTrustRefreshRunner;

impl CommandLinuxTrustRefreshRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl LinuxTrustRefreshRunner for CommandLinuxTrustRefreshRunner {
    fn refresh(&self) -> DomainResult<()> {
        let status = Command::new("update-ca-certificates")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                refresh_error(format!("update-ca-certificates could not start: {error}"))
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(refresh_error(format!(
                "update-ca-certificates exited with status {status}"
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinuxTrustSnapshot {
    schema_version: u32,
    previous_exists: bool,
    previous_contents: String,
    applied_contents: String,
}

pub fn apply_linux_trust<R: LinuxTrustRefreshRunner>(
    runner: &R,
    request: &LinuxTrustApplyRequest,
) -> DomainResult<LinuxTrustApplyReport> {
    validate_paths(
        &request.certificate_path,
        &request.trust_file_path,
        &request.snapshot_path,
    )?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_TRUST_CONFIRMATION_REQUIRED_CODE,
            "linux trust mutation requires explicit confirmation",
        ));
    }
    reject_symlink(&request.certificate_path)?;
    reject_symlink(&request.trust_file_path)?;
    reject_symlink(&request.snapshot_path)?;

    let certificate = fs::read_to_string(&request.certificate_path).map_err(|error| {
        write_error(format!(
            "read CA certificate {}: {error}",
            request.certificate_path.display()
        ))
    })?;
    let certificate = certificate_pem_blocks(&certificate)?;
    if request.snapshot_path.exists() {
        return Err(DomainError::new(
            LINUX_TRUST_WRITE_FAILED_CODE,
            "refusing to overwrite an existing linux trust snapshot",
        ));
    }

    let (previous_exists, previous_contents) = match fs::read_to_string(&request.trust_file_path) {
        Ok(contents) => (true, contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, String::new()),
        Err(error) => return Err(write_error(format!("read existing trust file: {error}"))),
    };
    if previous_contents.contains("PRIVATE KEY") {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "refusing to snapshot a trust file containing private-key material",
        ));
    }
    let applied_contents = certificate;
    let snapshot = serde_json::to_string_pretty(&LinuxTrustSnapshot {
        schema_version: LINUX_TRUST_SCHEMA_VERSION,
        previous_exists,
        previous_contents: previous_contents.clone(),
        applied_contents: applied_contents.clone(),
    })
    .map_err(|error| write_error(format!("render linux trust snapshot: {error}")))?;
    write_new_file(&request.snapshot_path, snapshot.as_bytes())?;

    if let Err(error) = write_atomic_file(&request.trust_file_path, applied_contents.as_bytes()) {
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(write_error(format!("write linux trust file: {error}")));
    }
    if let Err(error) = verify_contents(&request.trust_file_path, &applied_contents) {
        recover_file(
            &request.trust_file_path,
            previous_exists,
            &previous_contents,
        );
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(error);
    }

    if let Err(error) = runner.refresh() {
        recover_file(
            &request.trust_file_path,
            previous_exists,
            &previous_contents,
        );
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(DomainError::new(
            LINUX_TRUST_REFRESH_FAILED_CODE,
            error.message,
        ));
    }

    Ok(LinuxTrustApplyReport {
        certificate_path: request.certificate_path.clone(),
        trust_file_path: request.trust_file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        previous_exists,
        verified: true,
        refreshed: true,
    })
}

pub fn rollback_linux_trust<R: LinuxTrustRefreshRunner>(
    runner: &R,
    request: &LinuxTrustRollbackRequest,
) -> DomainResult<LinuxTrustRollbackReport> {
    validate_rollback_paths(&request.trust_file_path, &request.snapshot_path)?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_TRUST_CONFIRMATION_REQUIRED_CODE,
            "linux trust rollback requires explicit confirmation",
        ));
    }
    reject_symlink(&request.trust_file_path)?;
    reject_symlink(&request.snapshot_path)?;
    let snapshot_contents = fs::read_to_string(&request.snapshot_path)
        .map_err(|error| rollback_error(format!("read linux trust snapshot: {error}")))?;
    let snapshot = serde_json::from_str::<LinuxTrustSnapshot>(&snapshot_contents)
        .map_err(|error| rollback_error(format!("parse linux trust snapshot: {error}")))?;
    if snapshot.schema_version != LINUX_TRUST_SCHEMA_VERSION {
        return Err(rollback_error(
            "linux trust snapshot schema version is unsupported".to_string(),
        ));
    }
    let current = match fs::read_to_string(&request.trust_file_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(rollback_error(format!(
                "read current linux trust file: {error}"
            )))
        }
    };
    if current != snapshot.applied_contents {
        return Err(DomainError::new(
            LINUX_TRUST_CONFLICT_CODE,
            "linux trust file changed outside NetworkCore; refusing rollback",
        ));
    }

    if snapshot.previous_exists {
        write_atomic_file(
            &request.trust_file_path,
            snapshot.previous_contents.as_bytes(),
        )
        .map_err(|error| rollback_error(format!("restore linux trust file: {error}")))?;
    } else if request.trust_file_path.exists() {
        fs::remove_file(&request.trust_file_path)
            .map_err(|error| rollback_error(format!("remove linux trust file: {error}")))?;
    }
    if let Err(error) = runner.refresh() {
        let _ = write_atomic_file(
            &request.trust_file_path,
            snapshot.applied_contents.as_bytes(),
        );
        return Err(DomainError::new(
            LINUX_TRUST_REFRESH_FAILED_CODE,
            error.message,
        ));
    }

    Ok(LinuxTrustRollbackReport {
        trust_file_path: request.trust_file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        restored_previous_file: snapshot.previous_exists,
        snapshot_retained: true,
        refreshed: true,
    })
}

fn validate_paths(certificate: &Path, trust_file: &Path, snapshot: &Path) -> DomainResult<()> {
    if !certificate.is_absolute()
        || !trust_file.is_absolute()
        || !snapshot.is_absolute()
        || certificate == trust_file
        || certificate == snapshot
        || trust_file == snapshot
    {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "linux trust requires distinct absolute certificate, trust, and snapshot paths",
        ));
    }
    Ok(())
}

fn validate_rollback_paths(trust_file: &Path, snapshot: &Path) -> DomainResult<()> {
    if !trust_file.is_absolute() || !snapshot.is_absolute() || trust_file == snapshot {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "linux trust rollback requires distinct absolute trust and snapshot paths",
        ));
    }
    Ok(())
}

/// Parses the certificate source and returns only its `CERTIFICATE` PEM
/// blocks, normalised to one block after another.
///
/// Any other PEM block (private keys in every encoding, certificate requests,
/// parameters, ...) rejects the whole input instead of being silently dropped,
/// so a combined "certificate + key" file never reaches the system trust
/// directory or the snapshot, and the caller learns the file was unsuitable.
fn certificate_pem_blocks(contents: &str) -> DomainResult<String> {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    const TAIL: &str = "-----";
    let invalid = |message: &str| DomainError::new(LINUX_TRUST_INVALID_CODE, message.to_string());
    // Defence in depth: no spelling of a private key header may pass, even
    // outside a well-formed block.
    if contents.contains("PRIVATE KEY") {
        return Err(invalid(
            "linux trust source must contain only public CA certificate PEM blocks and no private key",
        ));
    }
    let mut certificates = String::new();
    let mut open: Option<(String, String)> = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if let Some(label) = line
            .strip_prefix(BEGIN)
            .and_then(|rest| rest.strip_suffix(TAIL))
        {
            if open.is_some() {
                return Err(invalid("linux trust source has a nested PEM block"));
            }
            if label != "CERTIFICATE" {
                return Err(invalid(
                    "linux trust source must contain only CERTIFICATE PEM blocks",
                ));
            }
            open = Some((label.to_string(), String::new()));
            continue;
        }
        if let Some(label) = line
            .strip_prefix(END)
            .and_then(|rest| rest.strip_suffix(TAIL))
        {
            let Some((open_label, body)) = open.take() else {
                return Err(invalid("linux trust source has an unmatched PEM END line"));
            };
            if label != open_label || body.is_empty() {
                return Err(invalid(
                    "linux trust source has a malformed CERTIFICATE block",
                ));
            }
            certificates.push_str("-----BEGIN CERTIFICATE-----\n");
            certificates.push_str(&body);
            certificates.push_str("-----END CERTIFICATE-----\n");
            continue;
        }
        if line.starts_with("-----") {
            return Err(invalid("linux trust source has a malformed PEM boundary"));
        }
        if let Some((_, body)) = open.as_mut() {
            if !line.is_empty() {
                body.push_str(line);
                body.push('\n');
            }
        }
        // Text outside PEM blocks (for example "Bag Attributes" written by
        // export tools) is not copied into the trust file.
    }
    if open.is_some() {
        return Err(invalid(
            "linux trust source has an unterminated CERTIFICATE block",
        ));
    }
    if certificates.is_empty() {
        return Err(invalid(
            "linux trust source must contain a public CA certificate PEM and no private key",
        ));
    }
    Ok(certificates)
}

fn reject_symlink(path: &Path) -> DomainResult<()> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            format!("refusing to mutate symlink path {}", path.display()),
        ));
    }
    Ok(())
}

/// The snapshot carries the previous trust file and the applied certificate;
/// it is private to the administrator that created it.
const SNAPSHOT_FILE_MODE: u32 = 0o600;
/// Trust anchors are public certificates and must stay world-readable so
/// every TLS client on the host can load them; never wider than that.
const TRUST_FILE_MODE: u32 = 0o644;

fn write_new_file(path: &Path, contents: &[u8]) -> DomainResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    restrict_mode(&mut options, SNAPSHOT_FILE_MODE);
    let mut file = options
        .open(path)
        .map_err(|error| write_error(format!("create {}: {error}", path.display())))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|error| write_error(format!("write {}: {error}", path.display())))
}

fn write_atomic_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("networkcore-{}.tmp", std::process::id()));
    // A stale temporary from an interrupted run is ours to replace; never
    // follow a symlink planted at that name.
    match fs::symlink_metadata(&temporary) {
        Ok(_) => fs::remove_file(&temporary)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    restrict_mode(&mut options, TRUST_FILE_MODE);
    let result = options.open(&temporary).and_then(|mut file| {
        file.write_all(contents)?;
        // `mode` is filtered by the umask; set the exact mode explicitly.
        set_exact_mode(&file, TRUST_FILE_MODE)?;
        file.sync_all()
    });
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(mode);
}

#[cfg(not(unix))]
fn restrict_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(unix)]
fn set_exact_mode(file: &fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_exact_mode(_file: &fs::File, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn verify_contents(path: &Path, expected: &str) -> DomainResult<()> {
    let actual = fs::read_to_string(path)
        .map_err(|error| write_error(format!("verify {}: {error}", path.display())))?;
    if actual != expected {
        return Err(write_error(format!(
            "verified {} did not match requested content",
            path.display()
        )));
    }
    Ok(())
}

fn recover_file(path: &Path, previous_exists: bool, previous_contents: &str) {
    if previous_exists {
        let _ = write_atomic_file(path, previous_contents.as_bytes());
    } else {
        let _ = fs::remove_file(path);
    }
}

fn write_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_WRITE_FAILED_CODE, message)
}

fn rollback_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_ROLLBACK_FAILED_CODE, message)
}

fn refresh_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_REFRESH_FAILED_CODE, message)
}
