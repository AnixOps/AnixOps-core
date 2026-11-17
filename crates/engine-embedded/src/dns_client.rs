//! Asking the servers [`crate::dns_policy`] picked.
//!
//! The servers of a target are asked at once ([`crate::dns::race`]): the
//! first NOERROR answer wins and the slower exchanges are dropped; NXDOMAIN
//! wins only once no server has a better answer. When none of them answers
//! (every exchange failed, or only SERVFAIL / REFUSED came back), the
//! `fallback` servers are asked the same way, unless they are the same
//! servers. NXDOMAIN is an answer and never falls back, so a name that does
//! not exist is not sent on to another resolver.

use std::sync::Arc;

use engine_outbound::TcpOutbound;

use crate::dns::{self, OutboundFailure, Raced};
use crate::dns_cache::DnsPools;
use crate::dns_policy::DnsPolicy;

/// The outbound to reach server `index` of the policy through, `None` when
/// routing rejects it (no query is sent rather than one in the clear).
pub type OutboundFor<'a> = &'a (dyn Fn(usize) -> Option<Arc<dyn TcpOutbound>> + Send + Sync);

/// Sends `query` to the servers of `target`, then to the fallback servers
/// when they give no answer; see the module docs.
pub async fn resolve(
    policy: &DnsPolicy,
    target: usize,
    query: &[u8],
    outbound_for: OutboundFor<'_>,
    pools: &DnsPools,
) -> Result<Vec<u8>, OutboundFailure> {
    let first = ask(policy, policy.target(target), query, outbound_for, pools).await;
    if first.answered() {
        return first.into_result();
    }
    match policy.fallback() {
        Some(fallback) if policy.target(fallback) != policy.target(target) => {
            let second = ask(policy, policy.target(fallback), query, outbound_for, pools).await;
            // A SERVFAIL from the fallback is no better than the first one's.
            first.merge(second).into_result()
        }
        _ => first.into_result(),
    }
}

async fn ask(
    policy: &DnsPolicy,
    servers: &[usize],
    query: &[u8],
    outbound_for: OutboundFor<'_>,
    pools: &DnsPools,
) -> Raced {
    dns::race(servers.iter().map(|&server| async move {
        let Some(outbound) = outbound_for(server) else {
            return Err(OutboundFailure::ConnectRefused);
        };
        // Kept connections belong to one server through one outbound.
        let key = (server, Arc::as_ptr(&outbound) as *const () as usize);
        dns::exchange(
            &policy.servers()[server].upstream,
            outbound.as_ref(),
            query,
            policy.timeout(),
            Some((pools, key)),
        )
        .await
    }))
    .await
}
