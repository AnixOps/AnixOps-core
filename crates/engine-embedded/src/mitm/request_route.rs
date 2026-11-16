//! Routing each request of a decrypted connection on its own, as Surge
//! does after MITM: `URL-REGEX` and `USER-AGENT` rules see every request's
//! URL and `User-Agent`, not only the first request of a plain HTTP flow.
//!
//! A connection opens its origin through the outbound its host routes to.
//! When the rules look at requests ([`RequestRouter::request_route`] is not
//! `None`), every request is routed again before it is forwarded:
//!
//! - the same outbound: the request goes over the open origin connection;
//! - `REJECT`: the app gets `403 Forbidden` from here and the request never
//!   leaves the device;
//! - another outbound: HTTP/1.1 replaces the origin connection with one
//!   through that outbound; HTTP/2 opens a second origin connection through
//!   it (at most [`MAX_EXTRA_ORIGINS`] per app connection) and sends the
//!   stream there, so other streams are not disturbed.
//!
//! A config without such rules routes per connection exactly as before and
//! pays nothing per request.

use engine_outbound::sniff::HttpRequestHead;
use engine_outbound::{RequestRouter, TargetAddr, TcpOutbound};

/// The outbound name of a rejected request.
pub(super) const REJECT: &str = "REJECT";

/// Origin connections an HTTP/2 app connection may open besides its own,
/// one per other outbound its requests route to.
pub(super) const MAX_EXTRA_ORIGINS: usize = 4;

/// What to do with one request.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    /// Over the origin connection open now.
    Keep,
    /// Answer `403` locally.
    Reject,
    /// Through another outbound, named.
    Switch(String),
}

/// Per-request routing state of one decrypted connection.
pub(super) struct RequestRoutes<'a> {
    router: &'a dyn RequestRouter,
    pub(super) target: TargetAddr,
    /// The outbound the connection's own origin goes through.
    pub(super) connection: String,
}

impl<'a> RequestRoutes<'a> {
    /// `None` when `outbound` cannot route requests or no rule looks at
    /// them; then nothing is routed per request.
    pub(super) async fn new(outbound: &'a dyn TcpOutbound, target: &TargetAddr) -> Option<Self> {
        let router = outbound.request_router()?;
        let connection = router.request_route(target, None).await?;
        Some(Self {
            router,
            target: target.clone(),
            connection,
        })
    }

    /// Routes the request for `url` sent with `user_agent`, compared with
    /// the outbound `current` (the connection's own or the one HTTP/1.1
    /// switched to).
    pub(super) async fn decide(&self, current: &str, head: &HttpRequestHead) -> Decision {
        match self.router.request_route(&self.target, Some(head)).await {
            None => Decision::Keep,
            Some(name) if name == REJECT => Decision::Reject,
            Some(name) if name == current => Decision::Keep,
            Some(name) => Decision::Switch(name),
        }
    }

    pub(super) fn router(&self) -> &'a dyn RequestRouter {
        self.router
    }
}

/// What `URL-REGEX` and `USER-AGENT` rules see of a decrypted request.
pub(super) fn request_head(url: &str, user_agent: Option<&str>) -> HttpRequestHead {
    HttpRequestHead {
        user_agent: user_agent.map(str::to_string),
        url: Some(url.to_string()),
    }
}
