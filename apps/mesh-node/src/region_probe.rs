//! Region measurement and the probe responder of the managed mesh
//! (`docs/protocols/intranet-mesh-appendix.md` D.4, D.6, D.9).
//!
//! [`RegionRuntime::set`] takes the `region` object of each `PUT /v1/mesh`:
//!
//! - With a directory, a task measures every region: 1 to 5 minutes after
//!   it first has one (at once, after the start jitter, while the node has
//!   no region: the panel waits for these numbers to choose one), then
//!   every 6 hours plus up to 10 minutes. Each round goes into the history
//!   kept in `region-probe.json` in the state directory (0600), from which
//!   the region change suggestion is drawn. Border nodes (those with a
//!   responder) measure but never suggest.
//! - With a responder, its UDP sockets answer probes with the X25519 key in
//!   `keys/region-probe` (0600), made the first time and kept.
//!
//! Neither keys nor shared secrets are logged or put in the status.

use std::io::{self, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use outbound_mesh::config::encode_key;
use outbound_mesh::region::directory::{Directory, RegionSection};
use outbound_mesh::region::probe::{Responder, REQUEST_LEN};
use outbound_mesh::region::rfc3339;
use outbound_mesh::region::round::{self, RoundResult, START_JITTER};
use outbound_mesh::region::suggest::{
    whole_ms, History, Round, FIRST_ROUND_MAX_S, FIRST_ROUND_MIN_S, ROUND_INTERVAL_S,
    ROUND_JITTER_S,
};
use outbound_mesh::status::{
    RegionProbeStatus, RegionRtt, RegionSuggestion, ResponderCounters, ResponderFailure,
    ResponderStatus,
};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::serve;

/// History file in the state directory (D.6 item 2).
pub const HISTORY_FILE: &str = "region-probe.json";
/// Responder key file under `keys/` (D.9.3).
pub const RESPONDER_KEY: &str = "region-probe";
/// Sources idle this long are forgotten by the responder.
const SOURCE_IDLE: Duration = Duration::from_secs(60);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the measuring task works from; changed by each `PUT`.
#[derive(Clone, PartialEq)]
struct Input {
    directory: Directory,
    current: Option<String>,
    border: bool,
}

/// Shared between the task and the status.
#[derive(Default)]
struct Measured {
    history: History,
    last: Option<RoundResult>,
    measured_at: Option<u64>,
    next_at: Option<u64>,
    rejected: usize,
    border: bool,
}

struct ResponderRun {
    listen: Vec<SocketAddr>,
    public: Option<[u8; 32]>,
    listening: Vec<String>,
    failure: Option<ResponderFailure>,
    responder: Option<Arc<Mutex<Responder>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ResponderRun {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The region part of a managed mesh.
pub struct RegionRuntime {
    dir: PathBuf,
    measured: Arc<Mutex<Measured>>,
    input: Option<watch::Sender<Input>>,
    task: Option<JoinHandle<()>>,
    responder: Option<ResponderRun>,
}

impl Drop for RegionRuntime {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl RegionRuntime {
    /// Nothing runs until [`RegionRuntime::set`].
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            measured: Arc::new(Mutex::new(Measured::default())),
            input: None,
            task: None,
            responder: None,
        }
    }

    /// Applies the `region` object of a `PUT` (`None`: no measurement and
    /// no responder).
    pub fn set(&mut self, section: Option<RegionSection>) {
        let section = section.unwrap_or_default();
        self.set_responder(section.responder.clone());
        let border = section.responder.is_some();
        {
            let mut measured = lock(&self.measured);
            measured.border = border;
            if measured.history.region.as_deref() != section.current.as_deref()
                || measured.history.version == 0
            {
                let text = std::fs::read_to_string(self.dir.join(HISTORY_FILE)).unwrap_or_default();
                measured.history = History::load(&text, section.current.as_deref());
                measured.last = None;
                measured.measured_at = measured.history.rounds.last().map(|r| r.at);
                save_history(&self.dir, &measured.history);
            }
        }
        match section.directory {
            None => {
                self.input = None;
                if let Some(task) = self.task.take() {
                    task.abort();
                }
                let mut measured = lock(&self.measured);
                measured.next_at = None;
                measured.rejected = 0;
            }
            Some(directory) => {
                lock(&self.measured).rejected = directory.rejected;
                let input = Input {
                    directory,
                    current: section.current,
                    border,
                };
                let running = self.task.as_ref().is_some_and(|task| !task.is_finished());
                match &self.input {
                    Some(sender) if running => {
                        sender.send_if_modified(|old| {
                            let changed = *old != input;
                            *old = input.clone();
                            changed
                        });
                    }
                    _ => {
                        // The first wait is fixed here so `next_at` is in the
                        // status as soon as the `PUT` returns.
                        let wait = {
                            let mut m = lock(&self.measured);
                            let wait =
                                first_delay(&m.history, input.current.as_deref(), unix_now());
                            m.next_at = Some(unix_now() + wait);
                            wait
                        };
                        let (sender, receiver) = watch::channel(input);
                        let measured = Arc::clone(&self.measured);
                        let dir = self.dir.clone();
                        self.task = Some(tokio::spawn(measure_loop(dir, measured, receiver, wait)));
                        self.input = Some(sender);
                    }
                }
            }
        }
    }

    fn set_responder(&mut self, listen: Option<Vec<SocketAddr>>) {
        if self.responder.as_ref().map(|r| &r.listen) == listen.as_ref() {
            return;
        }
        self.responder = None;
        let Some(listen) = listen else { return };
        self.responder = Some(start_responder(&self.dir, listen));
    }

    /// `region_probe` of the status; `None` without a directory and
    /// without a responder.
    pub fn status(&self) -> Option<RegionProbeStatus> {
        let responder = self.responder.as_ref().map(|run| ResponderStatus {
            public_key: run.public.map(|key| encode_key(&key)).unwrap_or_default(),
            listening: run.listening.clone(),
            failure: run.failure.clone(),
            counters: run
                .responder
                .as_ref()
                .map(|r| {
                    let c = lock(r).counters;
                    ResponderCounters {
                        answered: c.answered,
                        malformed: c.malformed,
                        rate_limited: c.rate_limited,
                        low_order: c.low_order,
                    }
                })
                .unwrap_or_default(),
        });
        if self.input.is_none() && responder.is_none() {
            return None;
        }
        let measured = lock(&self.measured);
        let mut status = RegionProbeStatus {
            responder,
            rejected: measured.rejected,
            ..RegionProbeStatus::default()
        };
        if self.input.is_none() {
            return Some(status);
        }
        status.measured_at = measured.measured_at.map(rfc3339);
        status.next_at = measured.next_at.map(rfc3339);
        if let Some(last) = &measured.last {
            status.regions = last
                .regions
                .iter()
                .map(|(region, result)| RegionRtt {
                    region: region.clone(),
                    rtt_ms: result.rtt_ms,
                })
                .collect();
            status.unreachable = last.unreachable.clone();
        } else if let Some(round) = measured.history.rounds.last() {
            status.regions = round
                .regions
                .iter()
                .map(|(region, rtt)| RegionRtt {
                    region: region.clone(),
                    rtt_ms: *rtt,
                })
                .collect();
        }
        // TODO(#384): hide the suggestion while the network's
        // `region_request` is pending once the kernel reads that field.
        if !measured.border {
            status.suggestion = measured
                .history
                .suggestion(false)
                .map(|s| RegionSuggestion {
                    region: s.region,
                    current_median_ms: whole_ms(s.current_median_ms),
                    suggested_median_ms: whole_ms(s.suggested_median_ms),
                    since: rfc3339(s.since),
                });
        }
        Some(status)
    }

    /// The nearest border node of the current region in the latest round
    /// and its RTT, for `self.regionBasis`.
    pub fn current_border(&self) -> Option<(String, f64)> {
        let measured = lock(&self.measured);
        let current = measured.history.region.as_deref()?;
        let result = measured.last.as_ref()?.regions.get(current)?;
        Some((result.border.clone(), result.rtt_ms))
    }
}

/// Writes the history atomically (temporary file, then rename), 0600.
fn save_history(dir: &Path, history: &History) {
    let path = dir.join(HISTORY_FILE);
    let temporary = dir.join(format!("{HISTORY_FILE}.tmp"));
    let result = (|| -> io::Result<()> {
        let _ = std::fs::remove_file(&temporary);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Windows: the state directory's own access list applies.
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(&temporary)?;
        file.write_all(history.save().as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
}

/// Seconds until the next round: soon after the first directory (at once
/// while the node has no region), otherwise 6 hours after the last round
/// plus up to 10 minutes; never before the first-round delay after a
/// restart.
fn first_delay(history: &History, current: Option<&str>, now: u64) -> u64 {
    if current.is_none() {
        return 0;
    }
    let early = FIRST_ROUND_MIN_S
        + round::jitter(Duration::from_secs(FIRST_ROUND_MAX_S - FIRST_ROUND_MIN_S)).as_secs();
    match history.rounds.last() {
        Some(last) => {
            let due = last.at
                + ROUND_INTERVAL_S
                + round::jitter(Duration::from_secs(ROUND_JITTER_S)).as_secs();
            due.saturating_sub(now).max(early)
        }
        None => early,
    }
}

async fn measure_loop(
    dir: PathBuf,
    measured: Arc<Mutex<Measured>>,
    mut input: watch::Receiver<Input>,
    first_wait: u64,
) {
    let mut current = input.borrow().current.clone();
    let mut wait = first_wait;
    loop {
        lock(&measured).next_at = Some(unix_now() + wait);
        // A node without a region waits for a region: when one arrives the
        // schedule starts over (the history is new then).
        let woke = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => false,
            changed = input.changed() => {
                if changed.is_err() {
                    return;
                }
                true
            }
        };
        if woke {
            let now_current = input.borrow().current.clone();
            let m = lock(&measured);
            if now_current == current && current.is_some() {
                // Only the directory changed: keep the schedule.
                let next = m.next_at.unwrap_or(0);
                wait = next.saturating_sub(unix_now());
            } else {
                current = now_current;
                wait = first_delay(&m.history, current.as_deref(), unix_now());
            }
            continue;
        }
        tokio::time::sleep(round::jitter(START_JITTER)).await;
        let snapshot = input.borrow().clone();
        let result = round::measure(&snapshot.directory).await;
        let now = unix_now();
        {
            let mut m = lock(&measured);
            // The region may have changed during the round; such a round
            // belongs to no history.
            if m.history.region.as_deref() == snapshot.current.as_deref() {
                m.history.push(Round {
                    at: now,
                    regions: result.latencies(),
                });
                save_history(&dir, &m.history);
                m.last = Some(result);
                m.measured_at = Some(now);
            }
        }
        wait = ROUND_INTERVAL_S + round::jitter(Duration::from_secs(ROUND_JITTER_S)).as_secs();
    }
}

fn start_responder(dir: &Path, listen: Vec<SocketAddr>) -> ResponderRun {
    let mut run = ResponderRun {
        listen: listen.clone(),
        public: None,
        listening: Vec::new(),
        failure: None,
        responder: None,
        tasks: Vec::new(),
    };
    let path = dir.join("keys").join(RESPONDER_KEY);
    let key = match serve::static_key(&path) {
        Ok(key) => key,
        Err(error) => {
            run.failure = Some(ResponderFailure {
                code: "region_probe_key_failed",
                detail: error.detail().to_owned(),
            });
            return run;
        }
    };
    run.public = Some(key.public());
    let responder = Arc::new(Mutex::new(Responder::new(*key.private(), Instant::now())));
    run.responder = Some(Arc::clone(&responder));
    let mut failures = Vec::new();
    for address in listen {
        match bind(address) {
            Ok(socket) => {
                run.listening.push(address.to_string());
                run.tasks
                    .push(tokio::spawn(serve_socket(socket, Arc::clone(&responder))));
            }
            Err(error) => failures.push(format!("{address}: {error}")),
        }
    }
    if !failures.is_empty() {
        run.failure = Some(ResponderFailure {
            code: "region_probe_bind_failed",
            detail: failures.join("; "),
        });
    }
    run
}

/// Binds one UDP address; an IPv6 wildcard takes IPv6 only, so that it can
/// sit beside an IPv4 wildcard on the same port.
fn bind(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(address).or_else(|error| {
        if address.is_ipv6() {
            bind_v6_only(address)
        } else {
            Err(error)
        }
    })?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Windows binds an IPv6 socket to IPv6 only by default, so the plain bind
/// above already was one; its failure stands.
#[cfg(windows)]
fn bind_v6_only(_address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    Err(io::Error::from(io::ErrorKind::AddrInUse))
}

#[cfg(unix)]
fn bind_v6_only(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain socket(2) / setsockopt(2) / bind(2) on a descriptor we
    // own; it is closed on every error path and handed to UdpSocket on
    // success.
    unsafe {
        #[cfg(target_os = "linux")]
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        #[cfg(not(target_os = "linux"))]
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = std::net::UdpSocket::from_raw_fd(fd);
        #[cfg(not(target_os = "linux"))]
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let SocketAddr::V6(v6) = address else {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        };
        let mut raw: libc::sockaddr_in6 = std::mem::zeroed();
        raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        raw.sin6_port = v6.port().to_be();
        raw.sin6_addr.s6_addr = v6.ip().octets();
        raw.sin6_scope_id = v6.scope_id();
        if libc::bind(
            fd,
            (&raw as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }
}

async fn serve_socket(socket: UdpSocket, responder: Arc<Mutex<Responder>>) {
    // One byte more than a request, so a longer datagram is seen as such.
    let mut buf = [0u8; REQUEST_LEN + 1];
    let mut since_prune = Instant::now();
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            // Errors on an unconnected UDP socket are transient; do not
            // spin on them.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let now = Instant::now();
        let answer = {
            let mut responder = lock(&responder);
            if now.duration_since(since_prune) >= SOURCE_IDLE {
                responder.prune(now, SOURCE_IDLE);
                since_prune = now;
            }
            responder.handle(&buf[..len], from.ip(), now)
        };
        if let Ok(answer) = answer {
            // A failed send is the prober's lost probe.
            let _ = socket.send_to(&answer, from).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbound_mesh::net::IpNet;
    use outbound_mesh::region::directory::{Basis, Border, Region};
    use std::collections::BTreeMap;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("region-probe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_responder_answers_and_keeps_its_key() {
        let dir = temp_dir("responder");
        let mut runtime = RegionRuntime::new(&dir);
        let section = RegionSection {
            current: Some("eu".into()),
            basis: Some(Basis::Admin),
            directory: None,
            responder: Some(vec!["127.0.0.1:0".parse().unwrap()]),
        };
        runtime.set(Some(section.clone()));
        let status = runtime.status().expect("status");
        let responder = status.responder.expect("responder");
        assert_eq!(responder.failure, None);
        assert_eq!(responder.public_key.len(), 44);
        let first_key = responder.public_key.clone();
        assert!(status.suggestion.is_none());
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(dir.join("keys").join(RESPONDER_KEY)).unwrap();
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
                0o600
            );
        }

        // Measure against it on a known port (port 0 hides the bound one).
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut section = section;
        section.responder = Some(vec![listen]);
        runtime.set(Some(section.clone()));
        let status = runtime.status().unwrap().responder.unwrap();
        assert_eq!(status.public_key, first_key, "the key is kept");
        assert_eq!(status.listening, vec![listen.to_string()]);

        let private: [u8; 32] = std::fs::read(dir.join("keys").join(RESPONDER_KEY))
            .unwrap()
            .try_into()
            .unwrap();
        let key = outbound_mesh::secure::noise::KeyPair::from_private(private).public();
        assert_eq!(encode_key(&key), first_key);
        let directory = Directory {
            preferred: None,
            regions: vec![Region {
                code: "eu".into(),
                subnet: IpNet::parse("10.130.0.0/16").unwrap(),
                borders: vec![Border {
                    name: "self".into(),
                    probe: listen,
                    key,
                }],
            }],
            rejected: 0,
        };
        let result = round::measure(&directory).await;
        assert!(result.regions.contains_key("eu"), "{result:?}");
        let counters = runtime.status().unwrap().responder.unwrap().counters;
        assert_eq!(counters.answered, 10);

        runtime.set(None);
        assert!(runtime.status().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_bind_failure_is_reported_and_the_rest_listens() {
        let dir = temp_dir("bind");
        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let busy = taken.local_addr().unwrap();
        let mut runtime = RegionRuntime::new(&dir);
        runtime.set(Some(RegionSection {
            responder: Some(vec![busy, "127.0.0.1:0".parse().unwrap()]),
            ..RegionSection::default()
        }));
        let status = runtime.status().unwrap().responder.unwrap();
        assert_eq!(
            status.failure.as_ref().unwrap().code,
            "region_probe_bind_failed"
        );
        assert_eq!(status.listening.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_history_follows_the_current_region() {
        let dir = temp_dir("history");
        let mut history = History::new(Some("eu".into()));
        for i in 0..5u64 {
            history.push(Round {
                at: 1_700_000_000 + i * 6 * 3600,
                regions: [("eu".to_owned(), 200.0), ("ap".to_owned(), 100.0)]
                    .into_iter()
                    .collect(),
            });
        }
        save_history(&dir, &history);
        let directory = Directory::default();
        let mut runtime = RegionRuntime::new(&dir);
        let section = RegionSection {
            current: Some("eu".into()),
            basis: Some(Basis::Latency),
            directory: Some(directory),
            responder: None,
        };
        runtime.set(Some(section.clone()));
        let status = runtime.status().unwrap();
        let suggestion = status.suggestion.expect("suggestion from the saved rounds");
        assert_eq!(suggestion.region, "ap");
        assert_eq!(suggestion.current_median_ms, 200);
        assert!(status.next_at.is_some());
        // Moved to ap: the rounds are dropped, on disk too.
        let mut moved = section;
        moved.current = Some("ap".into());
        runtime.set(Some(moved));
        assert!(runtime.status().unwrap().suggestion.is_none());
        let text = std::fs::read_to_string(dir.join(HISTORY_FILE)).unwrap();
        assert!(History::load(&text, Some("ap")).rounds.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_first_round_comes_soon_or_six_hours_after_the_last() {
        let now = 1_800_000_000;
        assert_eq!(first_delay(&History::new(None), None, now), 0);
        let fresh = first_delay(&History::new(Some("eu".into())), Some("eu"), now);
        assert!((FIRST_ROUND_MIN_S..=FIRST_ROUND_MAX_S).contains(&fresh));
        let mut history = History::new(Some("eu".into()));
        history.push(Round {
            at: now - 3600,
            regions: BTreeMap::new(),
        });
        let later = first_delay(&history, Some("eu"), now);
        assert!(
            (5 * 3600..=5 * 3600 + ROUND_JITTER_S).contains(&later),
            "{later}"
        );
        let mut history = History::new(Some("eu".into()));
        history.push(Round {
            at: now - 7 * 3600,
            regions: BTreeMap::new(),
        });
        let overdue = first_delay(&history, Some("eu"), now);
        assert!((FIRST_ROUND_MIN_S..=FIRST_ROUND_MAX_S).contains(&overdue));
    }
}
