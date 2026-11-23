//! Standard TLS client transport for outbound protocols (Trojan, VMess/VLESS
//! over TLS, ...): rustls with the ring provider and Mozilla's WebPKI roots.
//!
//! Browser-shaped ClientHellos and REALITY live in `tls-mimic`; this crate is
//! the plain, verifying client. `insecure` turns WebPKI verification (trust
//! chain, name, validity) off for servers with self-signed certificates, as
//! share links allow with `allowInsecure=1`, but still checks the handshake
//! signatures.
//!
//! Certificate pins ([`TlsSettings::pinned_certificate_sha256`],
//! [`TlsSettings::pinned_public_key_sha256`]) are checked against the
//! server's leaf certificate with or without `insecure`: with it they take
//! WebPKI's place, without it they come on top of it. `insecure` without a
//! pin accepts any certificate, so building such a client logs a warning,
//! once per server name.
//!
//! Sessions resume: every configuration keeps tickets in a [`TicketStore`],
//! and a [`TlsConnector`] counts its handshakes and how many of them
//! resumed ([`TlsStats`]).

pub mod tickets;

use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use engine_outbound::BoxStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, HandshakeKind, RootCertStore,
    SignatureScheme,
};

pub use tickets::TicketStore;

/// TLS settings of one outbound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// SNI and the name the certificate must match.
    pub server_name: String,
    pub alpn: Vec<String>,
    /// Skip WebPKI verification (trust chain, name, validity). With a pin
    /// set, the server's certificate must still match it; without one, any
    /// certificate is accepted.
    pub insecure: bool,
    /// SHA-256 digests of the server's whole leaf certificate (DER), as
    /// Hysteria2 `pinSHA256` and Xray `pcs` give them.
    pub pinned_certificate_sha256: Vec<[u8; 32]>,
    /// SHA-256 digests of the leaf certificate's SubjectPublicKeyInfo (DER).
    /// The leaf has to match one pin of either list.
    pub pinned_public_key_sha256: Vec<[u8; 32]>,
}

impl TlsSettings {
    /// Whether any certificate pin is set.
    pub fn is_pinned(&self) -> bool {
        !self.pinned_certificate_sha256.is_empty() || !self.pinned_public_key_sha256.is_empty()
    }
}

/// Parses certificate pins as configs write them: SHA-256 digests in hex,
/// upper or lower case, optionally with `:` or `-` between the bytes (as
/// OpenSSL prints fingerprints). `None` when one of them is not a SHA-256
/// digest, so a typo fails the config instead of dropping the pin.
pub fn parse_sha256_pins(pins: &[String]) -> Option<Vec<[u8; 32]>> {
    pins.iter()
        .map(|pin| parse_sha256_hex(pin.as_str()))
        .collect()
}

fn parse_sha256_hex(text: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = text
        .trim()
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-'))
        .collect();
    if digits.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in digest.iter_mut().zip(pairs) {
        let high = char::from(*high).to_digit(16)?;
        let low = char::from(*low).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(digest)
}

/// Handshakes of a [`TlsConnector`].
#[derive(Debug, Default)]
pub struct TlsStats {
    pub handshakes: AtomicU64,
    /// Handshakes that resumed an earlier session.
    pub resumed: AtomicU64,
}

impl TlsStats {
    /// Share of handshakes that resumed, 0 to 1.
    pub fn resumption_rate(&self) -> f64 {
        let handshakes = self.handshakes.load(Ordering::Relaxed);
        if handshakes == 0 {
            return 0.0;
        }
        self.resumed.load(Ordering::Relaxed) as f64 / handshakes as f64
    }

    /// The counters as JSON, for an outbound's health.
    pub fn health_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tls_handshakes": self.handshakes.load(Ordering::Relaxed),
            "tls_resumed": self.resumed.load(Ordering::Relaxed),
            "tls_resumption_rate": (self.resumption_rate() * 1000.0).round() / 1000.0,
        })
    }
}

/// A configured client; cheap to clone and shared by every connection.
#[derive(Clone)]
pub struct TlsConnector {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
    stats: Arc<TlsStats>,
}

impl TlsConnector {
    pub fn new(settings: &TlsSettings) -> io::Result<Self> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("tls server name is invalid"))?;
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(client_config(settings)?)),
            server_name,
            stats: Arc::new(TlsStats::default()),
        })
    }

    /// Runs the handshake over `transport` and returns the encrypted stream.
    pub async fn connect(&self, transport: BoxStream) -> io::Result<BoxStream> {
        let stream = self
            .connector
            .connect(self.server_name.clone(), transport)
            .await?;
        self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
        if stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed) {
            self.stats.resumed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Box::new(stream))
    }

    /// Handshakes so far, shared by every clone.
    pub fn stats(&self) -> &Arc<TlsStats> {
        &self.stats
    }
}

/// The rustls client configuration for `settings` (roots, `insecure` and
/// pins, and ALPN), for transports that run TLS themselves, such as QUIC.
pub fn client_config(settings: &TlsSettings) -> io::Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("tls protocol versions are unavailable"))?;
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = if settings.insecure || settings.is_pinned() {
        let verifier = CertificateCheck::new(settings, provider, roots)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    config.resumption = Resumption::store(Arc::new(TicketStore::new()));
    Ok(config)
}

/// The server certificate check for `insecure` settings and for pins.
///
/// WebPKI runs first unless `insecure`. Then the leaf certificate has to
/// match one of the pins; `insecure` without pins accepts any certificate.
/// Only the leaf counts: without WebPKI the rest of the chain is whatever
/// the server sent, and anyone can send a copy of a pinned certificate
/// along with their own. Either way the handshake signature is verified with
/// the leaf's key, so the server has to hold the pinned certificate's
/// private key.
#[derive(Debug)]
struct CertificateCheck {
    provider: Arc<CryptoProvider>,
    /// `None` when `insecure`.
    webpki: Option<Arc<WebPkiServerVerifier>>,
    certificate_sha256: Vec<[u8; 32]>,
    public_key_sha256: Vec<[u8; 32]>,
}

impl CertificateCheck {
    fn new(
        settings: &TlsSettings,
        provider: Arc<CryptoProvider>,
        roots: RootCertStore,
    ) -> io::Result<Self> {
        let webpki = if settings.insecure {
            if !settings.is_pinned() {
                warn_unverified(&settings.server_name);
            }
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|_| invalid("tls root certificates are unavailable"))?,
            )
        };
        Ok(Self {
            provider,
            webpki,
            certificate_sha256: settings.pinned_certificate_sha256.clone(),
            public_key_sha256: settings.pinned_public_key_sha256.clone(),
        })
    }

    fn is_pinned(&self) -> bool {
        !self.certificate_sha256.is_empty() || !self.public_key_sha256.is_empty()
    }

    /// Whether `end_entity` matches one of the pins. The certificate is only
    /// parsed for public key pins.
    fn matches_pin(&self, end_entity: &CertificateDer<'_>) -> Result<bool, rustls::Error> {
        if !self.certificate_sha256.is_empty() {
            let digest = sha256(end_entity.as_ref());
            if self.certificate_sha256.contains(&digest) {
                return Ok(true);
            }
        }
        if !self.public_key_sha256.is_empty() {
            let certificate = ParsedCertificate::try_from(end_entity)?;
            let digest = sha256(certificate.subject_public_key_info().as_ref());
            if self.public_key_sha256.contains(&digest) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl ServerCertVerifier for CertificateCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(webpki) = &self.webpki {
            webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        if !self.is_pinned() || self.matches_pin(end_entity)? {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    digest
}

/// Server names [`warn_unverified`] already warned about.
static UNVERIFIED_WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// Most names kept; past that the set starts over, so it stays small.
const MAX_UNVERIFIED_WARNED: usize = 256;

/// Logs, once per server name, that a client accepts any certificate:
/// `insecure` without a pin lets anyone on the path stand in for the server
/// and read what the protocol sends, credentials included. Names only, never
/// settings.
fn warn_unverified(server_name: &str) {
    let first = {
        let mut warned = UNVERIFIED_WARNED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if warned.len() >= MAX_UNVERIFIED_WARNED {
            warned.clear();
        }
        warned.insert(server_name.to_owned())
    };
    if first {
        tracing::warn!(
            server_name,
            "tls certificates are not verified: insecure is set without a certificate pin"
        );
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PublicKeyData,
    };

    const NAME: &str = "pin.test";

    /// A root, a leaf for [`NAME`] it signed, and a self-signed leaf for the
    /// same name.
    struct Certificates {
        root: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        leaf_public_key: Vec<u8>,
        self_signed: CertificateDer<'static>,
    }

    fn certificates() -> Certificates {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "pin test root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = root_params.self_signed(&root_key).unwrap().der().clone();
        let issuer = Issuer::from_params(&root_params, &root_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![NAME.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .clone();
        let self_signed_key = KeyPair::generate().unwrap();
        let self_signed = CertificateParams::new(vec![NAME.to_owned()])
            .unwrap()
            .self_signed(&self_signed_key)
            .unwrap()
            .der()
            .clone();
        Certificates {
            root,
            leaf,
            leaf_public_key: leaf_key.subject_public_key_info(),
            self_signed,
        }
    }

    /// The check for `insecure` and pins, trusting `root`.
    fn check(
        insecure: bool,
        certificate_sha256: &[[u8; 32]],
        public_key_sha256: &[[u8; 32]],
        root: &CertificateDer<'static>,
    ) -> CertificateCheck {
        let settings = TlsSettings {
            server_name: NAME.to_owned(),
            insecure,
            pinned_certificate_sha256: certificate_sha256.to_vec(),
            pinned_public_key_sha256: public_key_sha256.to_vec(),
            ..TlsSettings::default()
        };
        let mut roots = RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        CertificateCheck::new(&settings, provider, roots).unwrap()
    }

    /// `None` when `chain` (leaf first) passes `check` for [`NAME`].
    fn verify(
        check: &CertificateCheck,
        chain: &[CertificateDer<'static>],
    ) -> Option<rustls::Error> {
        let name = ServerName::try_from(NAME).unwrap();
        check
            .verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now())
            .err()
    }

    const PIN_MISMATCH: Option<rustls::Error> = Some(rustls::Error::InvalidCertificate(
        CertificateError::ApplicationVerificationFailure,
    ));

    #[test]
    fn insecure_with_a_certificate_pin_takes_only_the_pinned_leaf() {
        let certs = certificates();
        let leaf = sha256(&certs.leaf);
        let mut other = leaf;
        other[0] ^= 0x80;

        let pinned = check(true, &[leaf], &[], &certs.root);
        assert_eq!(verify(&pinned, std::slice::from_ref(&certs.leaf)), None);
        assert_eq!(
            verify(&pinned, std::slice::from_ref(&certs.self_signed)),
            PIN_MISMATCH
        );
        // One of several pins is enough.
        let several = check(true, &[other, leaf], &[], &certs.root);
        assert_eq!(verify(&several, std::slice::from_ref(&certs.leaf)), None);
        assert_eq!(
            verify(
                &check(true, &[other], &[], &certs.root),
                std::slice::from_ref(&certs.leaf)
            ),
            PIN_MISMATCH
        );
        // Only the leaf counts: anyone can send a copy of the pinned
        // certificate behind their own.
        let root_pinned = check(true, &[sha256(&certs.root)], &[], &certs.root);
        assert_eq!(
            verify(
                &root_pinned,
                &[certs.self_signed.clone(), certs.root.clone()]
            ),
            PIN_MISMATCH
        );
        let leaf_behind = [certs.self_signed.clone(), certs.leaf.clone()];
        assert_eq!(verify(&pinned, &leaf_behind), PIN_MISMATCH);
    }

    #[test]
    fn public_key_pins_match_the_leaf_key() {
        let certs = certificates();
        let public_key = sha256(&certs.leaf_public_key);
        let mut other = public_key;
        other[31] ^= 1;

        let pinned = check(true, &[], &[public_key], &certs.root);
        assert_eq!(verify(&pinned, std::slice::from_ref(&certs.leaf)), None);
        assert_eq!(
            verify(&pinned, std::slice::from_ref(&certs.self_signed)),
            PIN_MISMATCH
        );
        // The certificate's digest is not its key's.
        let swapped = check(true, &[], &[sha256(&certs.leaf)], &certs.root);
        assert_eq!(
            verify(&swapped, std::slice::from_ref(&certs.leaf)),
            PIN_MISMATCH
        );
        // Either list can match.
        let both = check(true, &[sha256(&certs.self_signed)], &[other], &certs.root);
        assert_eq!(
            verify(&both, std::slice::from_ref(&certs.self_signed)),
            None
        );
        assert_eq!(
            verify(&both, std::slice::from_ref(&certs.leaf)),
            PIN_MISMATCH
        );
        // A leaf that does not parse fails instead of matching nothing quietly.
        let garbage = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        assert!(verify(&pinned, &[garbage]).is_some());
    }

    #[test]
    fn insecure_without_pins_accepts_any_certificate() {
        let certs = certificates();
        let unverified = check(true, &[], &[], &certs.root);
        assert_eq!(
            verify(&unverified, std::slice::from_ref(&certs.self_signed)),
            None
        );
        assert_eq!(verify(&unverified, std::slice::from_ref(&certs.leaf)), None);
    }

    #[test]
    fn without_insecure_pins_come_on_top_of_webpki() {
        let certs = certificates();
        let leaf = sha256(&certs.leaf);
        let mut other = leaf;
        other[7] ^= 1;

        let verified = check(false, &[], &[], &certs.root);
        assert_eq!(verify(&verified, std::slice::from_ref(&certs.leaf)), None);
        assert_eq!(
            verify(&verified, std::slice::from_ref(&certs.self_signed)),
            Some(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        );

        let pinned = check(false, &[leaf], &[], &certs.root);
        assert_eq!(verify(&pinned, std::slice::from_ref(&certs.leaf)), None);
        let public_key = check(false, &[], &[sha256(&certs.leaf_public_key)], &certs.root);
        assert_eq!(verify(&public_key, std::slice::from_ref(&certs.leaf)), None);
        assert_eq!(
            verify(
                &check(false, &[other], &[], &certs.root),
                std::slice::from_ref(&certs.leaf)
            ),
            PIN_MISMATCH
        );
        // A pinned certificate still has to be trusted without `insecure`.
        let self_signed = check(false, &[sha256(&certs.self_signed)], &[], &certs.root);
        assert_eq!(
            verify(&self_signed, std::slice::from_ref(&certs.self_signed)),
            Some(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        );
        // And valid for the name.
        let other_name = ServerName::try_from("other.test").unwrap();
        assert!(pinned
            .verify_server_cert(&certs.leaf, &[], &other_name, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn pins_parse_from_hex_with_or_without_separators() {
        let lower = "0123456789abcdef".repeat(4);
        let upper_colons = ["01:23:45:67:89:AB:CD:EF"; 4].join(":");
        let dashes = ["01-23-45-67-89-ab-cd-ef"; 4].join("-");
        let pins =
            parse_sha256_pins(&[lower.clone(), upper_colons, format!(" {dashes} ")]).unwrap();
        assert_eq!(pins.len(), 3);
        assert_eq!(
            pins[0][..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert!(pins.iter().all(|pin| *pin == pins[0]));
        assert_eq!(parse_sha256_pins(&[]), Some(Vec::new()));
        for bad in [
            lower[..62].to_owned(),
            format!("{lower}00"),
            lower.replace('a', "g"),
            // Base64 of a digest: the engine takes hex only.
            "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=".to_owned(),
            String::new(),
        ] {
            assert_eq!(parse_sha256_pins(&[lower.clone(), bad]), None);
        }
    }

    #[test]
    fn unverified_warnings_are_kept_once_per_name_and_bounded() {
        warn_unverified("warned-once.test");
        warn_unverified("warned-once.test");
        for index in 0..(2 * MAX_UNVERIFIED_WARNED) {
            warn_unverified(&format!("{index}.warned.test"));
        }
        let warned = UNVERIFIED_WARNED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(warned.len() <= MAX_UNVERIFIED_WARNED);
    }
}
