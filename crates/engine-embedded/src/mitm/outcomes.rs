//! What HTTPS decryption did per host: how many connections were decrypted,
//! how many failed and why, so the client can mark the domains decryption
//! does not work for (`mitm_hosts`).
//!
//! The common failure is certificate pinning: the app refuses the leaf this
//! engine issues and ends the handshake with a certificate alert, or simply
//! closes the connection. Others are the origin being unreachable or its own
//! TLS failing. Only host names, counts, times and fixed reason codes are
//! kept, never addresses or bytes; the table holds at most [`MAX_HOSTS`]
//! hosts, the least recently seen dropped first, and lasts until the engine
//! stops or `clear_mitm_hosts`.

use std::collections::HashMap;
use std::io;

use rustls::AlertDescription;
use serde::Serialize;

/// Hosts the table keeps.
pub(crate) const MAX_HOSTS: usize = 256;

/// Why a decrypted connection failed. The codes are part of the
/// `mitm_hosts` answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Failure {
    /// The app answered the leaf with a certificate alert (bad, unknown CA,
    /// unknown, unsupported, revoked, expired) or `access_denied`: it does
    /// not trust the root, or it pins its certificate.
    ClientRejectedCertificate,
    /// The app closed the connection during the handshake without saying
    /// why, which certificate pinning often looks like.
    ClientClosed,
    /// The app sent another alert, or the handshake broke another way.
    ClientHandshakeFailed,
    /// The app did not finish the handshake in time.
    ClientTimeout,
    /// The origin's TLS failed, for example its certificate is not valid
    /// for the name.
    OriginTls,
    /// The origin could not be reached, or did not answer in time.
    OriginUnreachable,
}

impl Failure {
    /// The failure of the app's side of the handshake.
    pub(crate) fn client(error: &io::Error) -> Self {
        if error.kind() == io::ErrorKind::TimedOut {
            return Self::ClientTimeout;
        }
        match tls_error(error) {
            Some(rustls::Error::AlertReceived(alert)) if certificate_alert(*alert) => {
                Self::ClientRejectedCertificate
            }
            Some(_) => Self::ClientHandshakeFailed,
            None => match error.kind() {
                io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe => Self::ClientClosed,
                _ => Self::ClientHandshakeFailed,
            },
        }
    }

    /// The failure of the origin connection.
    pub(crate) fn origin(error: &io::Error) -> Self {
        if tls_error(error).is_some() {
            Self::OriginTls
        } else {
            Self::OriginUnreachable
        }
    }
}

fn tls_error(error: &io::Error) -> Option<&rustls::Error> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
}

fn certificate_alert(alert: AlertDescription) -> bool {
    matches!(
        alert,
        AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::AccessDenied
    )
}

/// One host of the `mitm_hosts` answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct HostOutcome {
    pub host: String,
    /// Connections whose both handshakes completed.
    pub decrypted: u64,
    pub failed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_decrypted_at_ms: Option<u64>,
    /// Failures by reason, for hosts that fail more than one way.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub failures: HashMap<&'static str, u64>,
    #[serde(skip)]
    seen: u64,
}

/// The per-host table.
#[derive(Default)]
pub(crate) struct HostOutcomes {
    hosts: HashMap<String, HostOutcome>,
    /// Bumped on every record, so the least recently seen host is known.
    clock: u64,
}

impl HostOutcomes {
    pub(crate) fn decrypted(&mut self, host: &str, at_ms: u64) {
        let entry = self.entry(host);
        entry.decrypted += 1;
        entry.last_decrypted_at_ms = Some(at_ms);
    }

    pub(crate) fn failed(&mut self, host: &str, failure: Failure, at_ms: u64) {
        let entry = self.entry(host);
        entry.failed += 1;
        entry.last_failure = Some(failure);
        entry.last_failure_at_ms = Some(at_ms);
        *entry.failures.entry(failure.code()).or_default() += 1;
    }

    pub(crate) fn clear(&mut self) {
        self.hosts.clear();
    }

    /// Every host, the most recently seen first.
    pub(crate) fn snapshot(&self) -> Vec<HostOutcome> {
        let mut hosts = self.hosts.values().cloned().collect::<Vec<_>>();
        hosts.sort_by_key(|outcome| std::cmp::Reverse(outcome.seen));
        hosts
    }

    fn entry(&mut self, host: &str) -> &mut HostOutcome {
        self.clock += 1;
        let clock = self.clock;
        let host = host.to_ascii_lowercase();
        if !self.hosts.contains_key(&host) && self.hosts.len() >= MAX_HOSTS {
            if let Some(oldest) = self
                .hosts
                .values()
                .min_by_key(|outcome| outcome.seen)
                .map(|outcome| outcome.host.clone())
            {
                self.hosts.remove(&oldest);
            }
        }
        let entry = self
            .hosts
            .entry(host.clone())
            .or_insert_with(|| HostOutcome {
                host,
                ..HostOutcome::default()
            });
        entry.seen = clock;
        entry
    }
}

impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::ClientRejectedCertificate => "client_rejected_certificate",
            Self::ClientClosed => "client_closed",
            Self::ClientHandshakeFailed => "client_handshake_failed",
            Self::ClientTimeout => "client_timeout",
            Self::OriginTls => "origin_tls",
            Self::OriginUnreachable => "origin_unreachable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(error: rustls::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    #[test]
    fn classifies_the_apps_side() {
        let pinned = tls(rustls::Error::AlertReceived(
            AlertDescription::BadCertificate,
        ));
        assert_eq!(Failure::client(&pinned), Failure::ClientRejectedCertificate);
        let unknown_ca = tls(rustls::Error::AlertReceived(AlertDescription::UnknownCA));
        assert_eq!(
            Failure::client(&unknown_ca),
            Failure::ClientRejectedCertificate
        );
        let other = tls(rustls::Error::AlertReceived(
            AlertDescription::ProtocolVersion,
        ));
        assert_eq!(Failure::client(&other), Failure::ClientHandshakeFailed);
        let closed = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert_eq!(Failure::client(&closed), Failure::ClientClosed);
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(Failure::client(&reset), Failure::ClientClosed);
        let slow = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(Failure::client(&slow), Failure::ClientTimeout);
    }

    #[test]
    fn classifies_the_origin() {
        let bad = tls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ));
        assert_eq!(Failure::origin(&bad), Failure::OriginTls);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(Failure::origin(&refused), Failure::OriginUnreachable);
    }

    #[test]
    fn counts_per_host_and_drops_the_least_recently_seen() {
        let mut table = HostOutcomes::default();
        table.decrypted("API.example.com", 10);
        table.failed("api.example.com", Failure::ClientClosed, 20);
        table.failed("api.example.com", Failure::ClientRejectedCertificate, 30);
        let snapshot = table.snapshot();
        assert_eq!(snapshot.len(), 1);
        let api = &snapshot[0];
        assert_eq!(api.host, "api.example.com");
        assert_eq!((api.decrypted, api.failed), (1, 2));
        assert_eq!(api.last_failure, Some(Failure::ClientRejectedCertificate));
        assert_eq!(api.last_failure_at_ms, Some(30));
        assert_eq!(api.last_decrypted_at_ms, Some(10));
        assert_eq!(api.failures.get("client_closed"), Some(&1));
        let json = serde_json::to_value(api).unwrap();
        assert_eq!(json["last_failure"], "client_rejected_certificate");
        assert!(json.get("seen").is_none());

        for index in 0..MAX_HOSTS {
            table.decrypted(&format!("h{index}.test"), 40);
        }
        let snapshot = table.snapshot();
        assert_eq!(snapshot.len(), MAX_HOSTS);
        assert!(snapshot
            .iter()
            .all(|outcome| outcome.host != "api.example.com"));
        assert_eq!(snapshot[0].host, format!("h{}.test", MAX_HOSTS - 1));

        table.clear();
        assert!(table.snapshot().is_empty());
    }
}
