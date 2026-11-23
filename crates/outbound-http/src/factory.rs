//! Registry entry for `"type": "http"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_tls::{parse_sha256_pins, TlsSettings};

use crate::{HttpCredentials, HttpOutbound};

pub const TYPE_NAME: &str = "http";

/// Has no `Debug`: the password is the credential.
#[derive(Deserialize)]
struct HttpSettings {
    server: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// HTTPS proxy: talk to the proxy over TLS.
    #[serde(default)]
    tls: bool,
    /// SNI for `tls`; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    /// Skip WebPKI verification for `tls`; the pins below still apply.
    #[serde(default)]
    insecure: bool,
    /// SHA-256 digests of the proxy's leaf certificate in hex, for `tls`.
    #[serde(default)]
    pinned_certificate_sha256: Vec<String>,
    /// SHA-256 digests of the leaf certificate's public key (SPKI) in hex,
    /// for `tls`.
    #[serde(default)]
    pinned_public_key_sha256: Vec<String>,
}

pub struct HttpFactory;

impl OutboundFactory for HttpFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: HttpSettings =
            parse_settings(settings, "http proxy settings are missing or invalid")?;
        let credentials = match (settings.username, settings.password) {
            (None, None) => None,
            (Some(username), password) => Some(HttpCredentials {
                username,
                password: password.unwrap_or_default(),
            }),
            (None, Some(_)) => return Err("http proxy password is set without a username"),
        };
        let pinned_certificate_sha256 = parse_sha256_pins(&settings.pinned_certificate_sha256)
            .ok_or("http proxy certificate pins are invalid")?;
        let pinned_public_key_sha256 = parse_sha256_pins(&settings.pinned_public_key_sha256)
            .ok_or("http proxy certificate pins are invalid")?;
        if !settings.tls
            && (!pinned_certificate_sha256.is_empty() || !pinned_public_key_sha256.is_empty())
        {
            // Without TLS there is no certificate to check the pins against.
            return Err("http proxy certificate pins need tls");
        }
        let tls = settings.tls.then(|| TlsSettings {
            server_name: settings
                .server_name
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| settings.server.clone()),
            alpn: Vec::new(),
            insecure: settings.insecure,
            pinned_certificate_sha256,
            pinned_public_key_sha256,
        });
        let outbound = HttpOutbound::new(
            settings.server,
            settings.port,
            credentials,
            tls.as_ref(),
            dialer,
        )
        .map_err(|_| "http proxy outbound settings are invalid")?;
        Ok(Arc::new(outbound))
    }
}
