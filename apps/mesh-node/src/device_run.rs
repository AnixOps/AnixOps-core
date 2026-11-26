//! The device without the Agent (requirements R31, R32, R35;
//! `docs/deploy/mesh-device.md`): `enroll`, the `device` service,
//! `subnet-request` and `device-status`. The checks and bodies are in
//! [`crate::device`]; this module does the I/O: the state directory, HTTPS
//! to Control ([`crate::https`]), the managed mesh of this process
//! ([`crate::managed`]) and the local status socket
//! ([`crate::local_status`]).
//!
//! The device only reads its member configuration and reports; it takes no
//! instruction from Control (R31) and opens no listening port of its own
//! (R11). Tokens, credentials and network secrets never appear in logs,
//! errors or the status output.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use outbound_mesh::status::{valid_tag, ApplyError, ManagedNetwork, MeshControl};
use outbound_mesh::MeshConfig;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::time::Instant;

use crate::device::{self, Backoff, Network, Rejection, Sections, INTERVAL};
use crate::host::{Host, RealHost};
use crate::https::{Client, Response};
use crate::local_status;
use crate::managed::{ManagedMesh, FEATURES};

/// The default state directory, apart from anixcore's so the two never
/// share an instance ID.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/anixops-mesh/device";

/// Exit codes (`docs/deploy/mesh-device.md`, "子命令").
pub const EXIT_OTHER: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_TOKEN: u8 = 8;
pub const EXIT_UNREACHABLE: u8 = 9;
pub const EXIT_REFUSED: u8 = 10;

const ENROLL: &str = "/api/v5/mesh/device/enroll";
const CONFIG: &str = "/api/v5/mesh/device/config";
const REPORT: &str = "/api/v5/mesh/device/report";
const SUBNET_REQUEST: &str = "/api/v5/mesh/device/subnet-request";

/// Reports on a change come at most this often.
const CHANGE_INTERVAL: Duration = Duration::from_secs(10);
/// Longest credential file read.
const MAX_CREDENTIAL_FILE: u64 = 4096;

/// Why a command ends: its exit code, a kind and a detail without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub code: u8,
    pub kind: &'static str,
    pub detail: String,
}

impl Exit {
    fn new(code: u8, kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            detail: detail.into(),
        }
    }

    fn rejected(code: u8, kind: &'static str, rejection: &Rejection) -> Self {
        Self::new(code, kind, rejection.to_string())
    }
}

/// `device.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFile {
    pub schema_version: u32,
    pub control: String,
    /// Missing until the first enrolment succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<u64>,
    /// 32 random bytes, standard base64; kept for every later enrolment.
    pub device_key: String,
    /// Trust only this CA file instead of the built-in public roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
}

/// The files of a state directory.
struct State {
    dir: PathBuf,
}

impl State {
    fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn device(&self) -> PathBuf {
        self.dir.join("device.json")
    }
    fn token(&self) -> PathBuf {
        self.dir.join("token")
    }
    fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }
    fn socket(&self) -> PathBuf {
        self.dir.join("status.sock")
    }
    fn lock(&self) -> PathBuf {
        self.dir.join("device.lock")
    }

    /// Creates the directory (0700) when it is missing.
    fn prepare(&self, host: &dyn Host) -> Result<(), Exit> {
        host.create_dir_all(&self.dir, 0o700).map_err(|error| {
            Exit::new(
                EXIT_USAGE,
                "state",
                format!("{}: {error}", self.dir.display()),
            )
        })
    }

    /// A state file, `None` when it does not exist.
    fn read(&self, host: &dyn Host, path: &Path) -> Result<Option<Vec<u8>>, Exit> {
        match host.read_state(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Exit::new(
                EXIT_USAGE,
                "state",
                format!("{}: {error}", path.display()),
            )),
        }
    }

    fn write(&self, host: &dyn Host, path: &Path, contents: &[u8]) -> Result<(), Exit> {
        host.write_state(path, contents)
            .map_err(|error| Exit::new(EXIT_USAGE, "state", format!("{}: {error}", path.display())))
    }

    fn device_file(&self, host: &dyn Host) -> Result<Option<DeviceFile>, Exit> {
        let Some(bytes) = self.read(host, &self.device())? else {
            return Ok(None);
        };
        let file: DeviceFile = serde_json::from_slice(&bytes)
            .map_err(|_| Exit::new(EXIT_USAGE, "state", "device.json is not valid"))?;
        if file.schema_version != 1 || device::control_url(&file.control).is_err() {
            return Err(Exit::new(EXIT_USAGE, "state", "device.json is not valid"));
        }
        Ok(Some(file))
    }

    fn write_device_file(&self, host: &dyn Host, file: &DeviceFile) -> Result<(), Exit> {
        let text = serde_json::to_vec_pretty(file).unwrap_or_default();
        self.write(host, &self.device(), &text)
    }

    /// The device token; `None` when there is none or it is not valid.
    fn device_token(&self, host: &dyn Host) -> Result<Option<String>, Exit> {
        let Some(bytes) = self.read(host, &self.token())? else {
            return Ok(None);
        };
        Ok(std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| device::device_token(text).ok()))
    }

    /// The accepted networks of `config.json`; none when it is missing.
    fn networks(&self, host: &dyn Host) -> Result<Vec<Network>, Exit> {
        match self.read(host, &self.config())? {
            Some(bytes) => device::parse_config(&bytes)
                .map_err(|rejection| Exit::rejected(EXIT_USAGE, "state", &rejection)),
            None => Ok(Vec::new()),
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Exit> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| Exit::new(EXIT_OTHER, "runtime", error.to_string()))
}

fn client(file: &DeviceFile) -> Result<Client, Exit> {
    Client::new(&file.control, file.ca_file.as_deref())
        .map_err(|error| Exit::new(EXIT_USAGE, "control", error.to_string()))
}

/// A credential from a file: at most 4 KiB, trimmed.
fn read_credential(path: &Path) -> Result<String, Exit> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_CREDENTIAL_FILE).read_to_string(&mut text))
        .map_err(|error| {
            Exit::new(
                EXIT_USAGE,
                "token_file",
                format!("{}: {error}", path.display()),
            )
        })?;
    Ok(text)
}

/// A new device key: 32 bytes from the system's randomness.
fn new_device_key() -> Result<String, Exit> {
    let mut key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| Exit::new(EXIT_OTHER, "random", "system randomness is unavailable"))?;
    Ok(outbound_mesh::config::encode_key(&key))
}

/// The error code in a refusal body (`{"error":{"code"}}` or `{"code"}`),
/// only when it is a plain code.
pub fn refusal_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| value.get("code"))?
        .as_str()?;
    let plain = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    plain.then(|| code.to_owned())
}

fn log(event: &str, fields: Value) {
    let mut line = Map::new();
    line.insert("event".to_owned(), json!(event));
    if let Value::Object(fields) = fields {
        line.extend(fields);
    }
    eprintln!("{}", Value::Object(line));
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `seconds` since the Unix epoch as RFC 3339 in UTC.
pub fn rfc3339(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    // Days to a civil date (proleptic Gregorian), after H. Hinnant.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The managed networks of a `PUT /v1/mesh` body, checked as the kernel
/// checks them (`node-runtime` `mesh::parse`). Errors name the item and
/// the rule, never a value.
pub fn managed_networks(body: &Value) -> Result<Vec<ManagedNetwork>, String> {
    let items = body
        .get("networks")
        .and_then(Value::as_array)
        .ok_or("networks must be a list")?;
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Value::Object(item) = item else {
            return Err(format!("networks[{index}] must be an object"));
        };
        let mut item = item.clone();
        item.remove("type");
        let tag = match item.remove("tag") {
            Some(Value::String(tag)) if valid_tag(&tag) => tag,
            _ => return Err(format!("networks[{index}]: tag is not valid")),
        };
        let config: MeshConfig = serde_json::from_value(Value::Object(item)).map_err(|error| {
            let text = error.to_string();
            let names_only = ["unknown field", "missing field", "duplicate field"]
                .iter()
                .any(|prefix| text.starts_with(prefix));
            if names_only {
                format!("networks[{index}] ({tag}): {text}")
            } else {
                format!("networks[{index}] ({tag}): a value has the wrong type or is out of range")
            }
        })?;
        let settings = config
            .validate()
            .map_err(|reason| format!("networks[{index}] ({tag}): {reason}"))?;
        out.push(ManagedNetwork { tag, settings });
    }
    Ok(out)
}

/// Runs `networks` on `mesh`.
async fn apply(mesh: &ManagedMesh, networks: &[Network]) -> Result<(), String> {
    let body = device::kernel_body(networks, Sections::default());
    let managed = managed_networks(&body)?;
    mesh.apply(managed)
        .await
        .map(|_| ())
        .map_err(|error| match error {
            ApplyError::Invalid(message) | ApplyError::Failed(message) => message,
        })
}

/// Options of `enroll`.
pub struct EnrollOptions<'a> {
    pub control: &'a str,
    pub token_file: &'a Path,
    pub state_dir: &'a Path,
    pub latencies: &'a [String],
    pub ca_file: Option<&'a Path>,
}

/// `enroll`: joins with a one-time credential and keeps the device token
/// and the first configuration. Returns the device id.
pub fn enroll(options: &EnrollOptions<'_>) -> Result<Value, Exit> {
    let host = RealHost::default();
    let credential = read_credential(options.token_file)?;
    let credential = device::enroll_token(&credential)
        .map_err(|rejection| Exit::rejected(EXIT_USAGE, "usage", &rejection))?;
    let control = device::control_url(options.control)
        .map_err(|rejection| Exit::rejected(EXIT_USAGE, "usage", &rejection))?;
    let mut latencies = BTreeMap::new();
    for text in options.latencies {
        let (region, ms) = device::latency(text)
            .map_err(|rejection| Exit::rejected(EXIT_USAGE, "usage", &rejection))?;
        latencies.insert(region, ms);
    }
    let ca_file = match options.ca_file {
        Some(path) => Some(std::fs::canonicalize(path).map_err(|error| {
            Exit::new(
                EXIT_USAGE,
                "ca_file",
                format!("{}: {error}", path.display()),
            )
        })?),
        None => None,
    };
    let state = State::new(options.state_dir);
    state.prepare(&host)?;
    // The device key is made once and kept, also when an enrolment fails,
    // so that a retry after a lost answer uses the same key.
    let device_key = match state.device_file(&host)? {
        Some(file) => file.device_key,
        None => new_device_key()?,
    };
    let mut file = DeviceFile {
        schema_version: 1,
        control,
        device_id: None,
        device_key,
        ca_file,
    };
    state.write_device_file(&host, &file)?;
    let client = client(&file)?;
    let body = device::enroll_request(&credential, &file.device_key, &latencies, FEATURES)
        .map_err(|rejection| Exit::rejected(EXIT_USAGE, "usage", &rejection))?;
    let body = serde_json::to_vec(&body).unwrap_or_default();
    let response = runtime()?
        .block_on(client.request("POST", ENROLL, None, Some(&body)))
        .map_err(|error| Exit::new(EXIT_UNREACHABLE, "unreachable", error.to_string()))?;
    match response.status {
        201 => {}
        401 | 409 => {
            return Err(Exit::new(
                EXIT_TOKEN,
                "credential_refused",
                format!("Control answered {}", response.status),
            ))
        }
        status => {
            return Err(Exit::new(
                EXIT_UNREACHABLE,
                "unexpected_answer",
                format!("Control answered {status}"),
            ))
        }
    }
    let enrolled = device::parse_enrolled(&response.body)
        .map_err(|rejection| Exit::rejected(EXIT_UNREACHABLE, "invalid_answer", &rejection))?;
    file.device_id = Some(enrolled.device_id);
    state.write_device_file(&host, &file)?;
    state.write(&host, &state.token(), enrolled.device_token.as_bytes())?;
    state.write(
        &host,
        &state.config(),
        &device::config_file(&enrolled.networks),
    )?;
    Ok(json!({
        "ok": true,
        "device_id": enrolled.device_id,
        "networks": enrolled.networks.len(),
    }))
}

/// `subnet-request`: asks Control to let this full node advertise
/// `cidrs` (none withdraws the request).
pub fn subnet_request(state_dir: &Path, cidrs: &[String]) -> Result<Value, Exit> {
    let host = RealHost::default();
    let body = device::subnet_request(cidrs)
        .map_err(|rejection| Exit::rejected(EXIT_USAGE, "usage", &rejection))?;
    let state = State::new(state_dir);
    let file = state
        .device_file(&host)?
        .ok_or_else(|| Exit::new(EXIT_TOKEN, "not_enrolled", "the device is not enrolled"))?;
    let token = state
        .device_token(&host)?
        .ok_or_else(|| Exit::new(EXIT_TOKEN, "token_missing", "the device has no valid token"))?;
    let client = client(&file)?;
    let body = serde_json::to_vec(&body).unwrap_or_default();
    let response = runtime()?
        .block_on(client.request("POST", SUBNET_REQUEST, Some(&token), Some(&body)))
        .map_err(|error| Exit::new(EXIT_UNREACHABLE, "unreachable", error.to_string()))?;
    match response.status {
        202 => Ok(json!({ "ok": true })),
        401 => Err(Exit::new(
            EXIT_TOKEN,
            "token_refused",
            "Control answered 401",
        )),
        400 | 409 => Err(Exit::new(
            EXIT_REFUSED,
            "refused",
            refusal_code(&response.body).unwrap_or_else(|| format!("http_{}", response.status)),
        )),
        status => Err(Exit::new(
            EXIT_UNREACHABLE,
            "unexpected_answer",
            format!("Control answered {status}"),
        )),
    }
}

/// `device-status`: the service's snapshot through the local socket.
pub fn device_status(state_dir: &Path) -> Result<Value, Exit> {
    local_status::query(&State::new(state_dir).socket())
        .map_err(|error| Exit::new(EXIT_OTHER, "not_running", error.to_string()))
}

/// What the service shares with the status socket.
#[derive(Debug, Default)]
struct Shared {
    last_config: Option<u64>,
    last_report: Option<u64>,
    /// `ok`, `unreachable` or `rejected`.
    control_state: &'static str,
    advertise: Vec<String>,
}

/// How a request to Control went.
enum Outcome {
    /// The expected answer.
    Done(Response),
    /// 401: the token is no longer valid.
    TokenRefused,
    /// Try again after this wait.
    Later(Duration),
}

fn classify(answer: io::Result<Response>, expected: u16, backoff: &mut Backoff) -> Outcome {
    match answer {
        Ok(response) if response.status == expected => {
            backoff.succeeded();
            Outcome::Done(response)
        }
        Ok(response) if response.status == 401 => Outcome::TokenRefused,
        Ok(response) if response.status == 429 => {
            let wait = backoff.failed();
            Outcome::Later(device::retry_after(response.retry_after.as_deref()).unwrap_or(wait))
        }
        Ok(response) => {
            log("control_error", json!({ "status": response.status }));
            Outcome::Later(backoff.failed())
        }
        Err(error) => {
            log(
                "control_unreachable",
                json!({ "detail": error.to_string() }),
            );
            Outcome::Later(backoff.failed())
        }
    }
}

/// What a report says, without the figures that change all the time
/// (peer latencies): a change of it is reported early.
pub fn report_shape(report: &Value) -> Value {
    let mut shape = report.clone();
    if let Some(networks) = shape.get_mut("networks").and_then(Value::as_array_mut) {
        for network in networks {
            if let Some(peers) = network.get_mut("peers").and_then(Value::as_array_mut) {
                for peer in peers {
                    if let Value::Object(fields) = peer {
                        fields.remove("latency_ms");
                    }
                }
            }
        }
    }
    shape
}

/// 0-5 seconds, so that devices do not ask at the same moment.
fn jitter() -> Duration {
    let mut bytes = [0u8; 2];
    let _ = SystemRandom::new().fill(&mut bytes);
    Duration::from_millis(u64::from(u16::from_le_bytes(bytes)) % 5001)
}

/// `device`: the service. Returns when a stop signal comes; ends with
/// [`EXIT_TOKEN`] when the device has no valid token or Control refuses it.
pub fn device_service(state_dir: &Path) -> Result<(), Exit> {
    let host = RealHost::default();
    let state = State::new(state_dir);
    let file = state
        .device_file(&host)?
        .ok_or_else(|| Exit::new(EXIT_TOKEN, "not_enrolled", "the device is not enrolled"))?;
    let token = state
        .device_token(&host)?
        .ok_or_else(|| Exit::new(EXIT_TOKEN, "token_missing", "the device has no valid token"))?;
    let networks = state.networks(&host)?;
    let client = client(&file)?;
    match host.try_lock(
        &state.lock(),
        &format!("anixops-mesh device {}", std::process::id()),
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(Exit::new(
                EXIT_OTHER,
                "busy",
                "another device service runs on this state directory",
            ))
        }
        Err(error) => return Err(Exit::new(EXIT_USAGE, "state", error.to_string())),
    }
    let result = runtime()?.block_on(serve(&host, &state, file, token, networks, client));
    host.unlock(&state.lock());
    result
}

async fn serve(
    host: &dyn Host,
    state: &State,
    file: DeviceFile,
    token: String,
    mut networks: Vec<Network>,
    client: Client,
) -> Result<(), Exit> {
    use tokio::signal::unix::{signal, SignalKind};

    let mesh = Arc::new(
        ManagedMesh::open(&state.dir)
            .map_err(|error| Exit::new(EXIT_OTHER, "mesh", error.to_string()))?,
    );
    let shared = Arc::new(Mutex::new(Shared {
        control_state: "ok",
        advertise: device::approved_advertise(&networks),
        ..Shared::default()
    }));
    // The kept configuration runs even while Control cannot be reached.
    if let Err(detail) = apply(&mesh, &networks).await {
        log(
            "config_rejected",
            json!({ "source": "config.json", "detail": detail }),
        );
    }
    match local_status::bind(&state.socket()) {
        Ok(listener) => {
            let mesh = Arc::clone(&mesh);
            let shared = Arc::clone(&shared);
            let device_id = file.device_id;
            let control = file.control.clone();
            tokio::spawn(local_status::serve(listener, move || {
                snapshot(&mesh, &shared, device_id, &control)
            }));
        }
        Err(error) => log("status_socket", json!({ "detail": error.to_string() })),
    }
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| Exit::new(EXIT_OTHER, "signal", error.to_string()))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| Exit::new(EXIT_OTHER, "signal", error.to_string()))?;
    let mut config_backoff = Backoff::default();
    let mut report_backoff = Backoff::default();
    let mut next_config = Instant::now();
    let mut next_report = Instant::now() + CHANGE_INTERVAL;
    let mut last_report_at: Option<Instant> = None;
    let mut last_shape = Value::Null;
    let mut check = tokio::time::interval(CHANGE_INTERVAL);
    let features = FEATURES.join(",");
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(next_config) => {
                let answer = client
                    .request("GET", &format!("{CONFIG}?features={features}"), Some(&token), None)
                    .await;
                match classify(answer, 200, &mut config_backoff) {
                    Outcome::Done(response) => {
                        let now = now_unix();
                        let rejected = match device::parse_config(&response.body) {
                            Ok(fresh) if fresh == networks => false,
                            Ok(fresh) => match apply(&mesh, &fresh).await {
                                Ok(()) => {
                                    if let Err(exit) = state.write(host, &state.config(), &device::config_file(&fresh)) {
                                        log("config_not_saved", json!({ "detail": exit.detail }));
                                    }
                                    networks = fresh;
                                    false
                                }
                                Err(detail) => {
                                    log("config_rejected", json!({ "detail": detail }));
                                    // Back to what ran before.
                                    let _ = apply(&mesh, &networks).await;
                                    true
                                }
                            },
                            Err(rejection) => {
                                log("config_rejected", json!({ "field": rejection.field, "rule": rejection.rule }));
                                true
                            }
                        };
                        let mut shared = lock(&shared);
                        shared.last_config = Some(now);
                        shared.control_state = if rejected { "rejected" } else { "ok" };
                        shared.advertise = device::approved_advertise(&networks);
                        next_config = Instant::now() + INTERVAL + jitter();
                    }
                    Outcome::TokenRefused => return token_refused(host, state, &mesh).await,
                    Outcome::Later(wait) => {
                        lock(&shared).control_state = "unreachable";
                        next_config = Instant::now() + wait;
                    }
                }
            }
            _ = tokio::time::sleep_until(next_report) => {
                let status = serde_json::to_value(mesh.status()).unwrap_or(Value::Null);
                let report = device::report_body(&status, FEATURES, None);
                let body = serde_json::to_vec(&report).unwrap_or_default();
                let answer = client.request("POST", REPORT, Some(&token), Some(&body)).await;
                match classify(answer, 204, &mut report_backoff) {
                    Outcome::Done(_) => {
                        last_shape = report_shape(&report);
                        last_report_at = Some(Instant::now());
                        lock(&shared).last_report = Some(now_unix());
                        next_report = Instant::now() + INTERVAL;
                    }
                    Outcome::TokenRefused => return token_refused(host, state, &mesh).await,
                    Outcome::Later(wait) => {
                        lock(&shared).control_state = "unreachable";
                        next_report = Instant::now() + wait;
                    }
                }
            }
            _ = check.tick() => {
                // A change goes out early, at most every 10 seconds, while
                // Control answers.
                let status = serde_json::to_value(mesh.status()).unwrap_or(Value::Null);
                let shape = report_shape(&device::report_body(&status, FEATURES, None));
                let quiet = last_report_at.is_none_or(|at| at.elapsed() >= CHANGE_INTERVAL);
                if shape != last_shape && quiet && report_backoff.wait() == INTERVAL {
                    next_report = next_report.min(Instant::now());
                }
            }
            _ = terminate.recv() => return stop(state, &mesh).await,
            _ = interrupt.recv() => return stop(state, &mesh).await,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The status socket's answer.
fn snapshot(
    mesh: &ManagedMesh,
    shared: &Mutex<Shared>,
    device_id: Option<u64>,
    control: &str,
) -> Value {
    let shared = lock(shared);
    json!({
        "ok": true,
        "device": {
            "device_id": device_id,
            "control": control,
            "last_config": shared.last_config.map(rfc3339),
            "last_report": shared.last_report.map(rfc3339),
            "control_state": shared.control_state,
            "advertise": shared.advertise,
        },
        "mesh": serde_json::to_value(mesh.status()).unwrap_or(Value::Null),
    })
}

async fn stop(state: &State, mesh: &ManagedMesh) -> Result<(), Exit> {
    let _ = mesh.apply(Vec::new()).await;
    let _ = std::fs::remove_file(state.socket());
    log("stopped", json!({}));
    Ok(())
}

/// Control refused the token: the networks stop, the token goes, and the
/// service ends with [`EXIT_TOKEN`] until an administrator issues a new
/// credential.
async fn token_refused(host: &dyn Host, state: &State, mesh: &ManagedMesh) -> Result<(), Exit> {
    let _ = mesh.apply(Vec::new()).await;
    let _ = host.remove_file(&state.token());
    let _ = std::fs::remove_file(state.socket());
    Err(Exit::new(
        EXIT_TOKEN,
        "token_refused",
        "Control refused the device token; enroll again",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_written_in_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_795_640_400), "2026-11-25T21:00:00Z");
        assert_eq!(rfc3339(4_107_542_399), "2100-02-28T23:59:59Z");
    }

    #[test]
    fn refusal_codes_are_taken_only_when_plain() {
        assert_eq!(
            refusal_code(br#"{"error":{"code":"mesh_conflict","message":"x"}}"#).as_deref(),
            Some("mesh_conflict")
        );
        assert_eq!(
            refusal_code(br#"{"code":"invalid_request"}"#).as_deref(),
            Some("invalid_request")
        );
        assert_eq!(refusal_code(br#"{"error":{"code":"Has Spaces"}}"#), None);
        assert_eq!(refusal_code(b"not json"), None);
    }

    #[test]
    fn latencies_do_not_count_as_a_change() {
        let report = |latency: u64, running: bool| {
            json!({
                "networks": [{
                    "id": "cn",
                    "running": running,
                    "peers": [{ "address": "10.150.0.1", "latency_ms": latency }],
                }],
            })
        };
        assert_eq!(
            report_shape(&report(10, true)),
            report_shape(&report(99, true))
        );
        assert_ne!(
            report_shape(&report(10, true)),
            report_shape(&report(10, false))
        );
    }

    #[test]
    fn device_networks_become_the_kernels_managed_networks() {
        let body = json!({ "networks": [{
            "tag": "mesh-cn",
            "type": "mesh",
            "config_version": 1,
            "network": { "name": "mesh-cn", "secret": "s3cret-value", "secure_mode": true, "kind": "managed", "native_keys": [] },
            "node": { "address": "10.150.128.9/16" },
            "peers": [{ "server": "edge-1.example.com", "port": 11010, "transport": "tcp" }],
        }]});
        let networks = managed_networks(&body).unwrap();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].tag, "mesh-cn");
        let mut bad = body.clone();
        bad["networks"][0]["tag"] = json!("cn");
        assert!(managed_networks(&bad).is_err());
        let mut typo = body.clone();
        typo["networks"][0]["network"]["secret"] = json!(12345);
        let error = managed_networks(&typo).err().unwrap();
        assert!(!error.contains("12345"), "{error}");
    }

    #[test]
    fn the_device_file_keeps_its_fields() {
        let file = DeviceFile {
            schema_version: 1,
            control: "https://panel.example.com".to_owned(),
            device_id: Some(5),
            device_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            ca_file: None,
        };
        let text = serde_json::to_string(&file).unwrap();
        assert_eq!(
            text,
            r#"{"schema_version":1,"control":"https://panel.example.com","device_id":5,"device_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#
        );
        assert_eq!(serde_json::from_str::<DeviceFile>(&text).unwrap(), file);
        assert!(serde_json::from_str::<DeviceFile>(
            r#"{"schema_version":1,"control":"x","device_key":"k","extra":1}"#
        )
        .is_err());
    }
}
