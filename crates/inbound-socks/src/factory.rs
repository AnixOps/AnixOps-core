//! Registry entry for `"type": "socks"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{StreamInbound, User};
use serde::Deserialize;

use crate::SocksInbound;

pub const TYPE_NAME: &str = "socks";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksInboundSettings {
    users: Vec<User>,
}

pub struct SocksInboundFactory;

impl InboundFactory for SocksInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: SocksInboundSettings =
            parse_settings(settings, "socks inbound settings are missing or invalid")?;
        if settings.users.is_empty() {
            return Err("socks inbound needs at least one user");
        }
        let inbound = SocksInbound::new();
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(settings: serde_json::Value) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: Settings = serde_json::from_value(settings).unwrap();
        SocksInboundFactory.build(&settings)
    }

    #[test]
    fn needs_users_with_strong_passwords() {
        assert!(build(serde_json::json!({})).is_err());
        assert!(build(serde_json::json!({"users": []})).is_err());
        assert!(build(serde_json::json!({"users": [{"name": "a", "password": "short"}]})).is_err());
        assert!(build(serde_json::json!({"users": [{"name": "a"}]})).is_err());
        let inbound = build(serde_json::json!({
            "users": [{"name": "7", "username": "tmp-7", "password": "0123456789abcdef"}]
        }))
        .unwrap();
        assert_eq!(inbound.protocol(), "socks");
        assert!(inbound.serves_connections());
        assert_eq!(inbound.users().len(), 1);
    }

    #[test]
    fn refuses_unknown_settings() {
        assert!(build(serde_json::json!({
            "users": [{"name": "a", "password": "0123456789abcdef"}],
            "udp": true
        }))
        .is_err());
    }
}
