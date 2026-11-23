//! The rule sets of a routing config: inline lists, and remote lists the
//! engine downloads again on a schedule while it runs.
//!
//! `RULE-SET,<name>` rules match the set `<name>`; `GEOSITE,<category>` rules
//! the set `geosite-<category>` and `GEOIP,<CC>` rules the set `geoip-<cc>`
//! (lower case), so a client supplies GeoSite and GeoIP data as ordinary
//! lists. A remote set is replaced atomically after each successful
//! download; a failed one keeps the previous entries and is retried sooner.
//! URLs never appear in status.
//!
//! With a cache directory (`routing.rule_set_cache_dir`, see
//! [`crate::rule_set_cache`]) every successful download is also kept on
//! disk, and a remote set starts with its last good download instead of
//! empty: it is downloaded again an interval after that download, right
//! away when there is no usable copy. Without one a remote set starts with
//! its inline entries (possibly empty), is downloaded right away when they
//! are empty and an interval later when they are not.
//!
//! A remote set may carry an Ed25519 `public_key`: each download then also
//! fetches the detached signature (`signature_url`, `<url>.sig` by default)
//! and installs the list only when the signature over its exact bytes
//! verifies ([`verify_list_signature`]). A missing or wrong signature keeps
//! the previous entries like any failed download.
//!
//! The set [`LAN_RULE_SET`] (Surge's built-in `LAN`) is always there unless
//! the config names its own. A downloaded list may hold rule types no set
//! can (`IP-ASN`, `SCRIPT`, ...): they are counted by type in
//! [`RuleSetStatus::skipped`] so the client can say what the set ignores.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config_core::rule_set::{BareDomain, RuleSet, LAN_RULE_SET};
use serde::Serialize;
use tokio::sync::Notify;

use crate::rule_set_cache::RuleSetCache;

/// Shortest refresh interval accepted for a remote set.
pub const MIN_UPDATE_INTERVAL_SECS: u32 = 600;
pub const DEFAULT_UPDATE_INTERVAL_SECS: u32 = 86_400;
/// How soon a failed download is tried again, at most.
pub const RETRY_INTERVAL_SECS: u32 = 300;
/// Largest list accepted from a download or the cache directory.
pub const MAX_LIST_BYTES: usize = 32 * 1024 * 1024;

/// A list the engine downloads itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRuleSet {
    pub name: String,
    pub url: String,
    pub interval_secs: u32,
    pub bare: BareDomain,
    /// The outbound the download goes through: a policy group, a node or
    /// `DIRECT`.
    pub via: String,
    /// When set, a list is installed only with a valid signature.
    pub signature: Option<RuleSetSignature>,
}

/// How a remote set's downloads are verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSetSignature {
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// Where the detached signature of the list is.
    pub url: String,
}

/// Largest signature file accepted: a base64 signature with some slack for
/// a trailing newline or a minisign-style comment line.
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// Checks an Ed25519 signature over the exact bytes of a downloaded list.
///
/// `signature` is the signature file: the 64-byte signature in standard or
/// URL-safe base64 (padding optional) on its own line. Blank lines and lines
/// starting with `#` or `untrusted comment:` are skipped, so a file with a
/// comment header works too.
#[cfg(feature = "local-proxy")]
pub fn verify_list_signature(
    public_key: &[u8; 32],
    body: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let text = std::str::from_utf8(signature).map_err(|_| "signature_malformed")?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty() && !line.starts_with('#') && !line.starts_with("untrusted comment:")
        })
        .ok_or("signature_malformed")?;
    let bytes = decode_base64(line).ok_or("signature_malformed")?;
    if bytes.len() != 64 {
        return Err("signature_malformed");
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(body, &bytes)
        .map_err(|_| "signature_invalid")
}

/// Standard or URL-safe base64, with or without padding.
#[cfg(feature = "local-proxy")]
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let text = text.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok())
}

/// One rule set as the client's rule page shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleSetStatus {
    pub name: String,
    /// `inline` or `remote`.
    pub source: &'static str,
    pub entries: usize,
    /// Unix milliseconds of the last successful download; with
    /// `from_cache`, the download (of an earlier run) the kept copy comes
    /// from.
    pub updated_at_ms: Option<u64>,
    /// Why the last download failed, cleared by the next success.
    pub last_error: Option<&'static str>,
    /// Whether downloads must carry a valid signature.
    pub signed: bool,
    /// Lines of the last download that the set could not hold, by rule type
    /// (such as `IP-ASN` or `SCRIPT`; `INVALID` for malformed lines, `OTHER`
    /// past sixteen types). Empty when nothing was skipped.
    pub skipped: BTreeMap<String, usize>,
    /// Whether the entries in force are the copy the cache directory kept,
    /// loaded at start; cleared by the next successful download. A remote
    /// set with neither this nor `updated_at_ms` was never downloaded.
    pub from_cache: bool,
    /// Why the last successful download could not be kept in the cache
    /// directory (`cache_write_failed`); cleared by the next one that was.
    /// Always `None` without a cache directory.
    pub cache_error: Option<&'static str>,
}

pub struct RuleSetStore {
    sets: RwLock<BTreeMap<String, Arc<RuleSet>>>,
    remotes: Vec<RemoteRuleSet>,
    /// Where downloads are kept between runs (`routing.rule_set_cache_dir`).
    cache: Option<RuleSetCache>,
    status: Mutex<BTreeMap<String, RuleSetStatus>>,
    refresh: Notify,
    /// Whether some set holds a `PROCESS-NAME` rule, or a `URL-REGEX` or
    /// `USER-AGENT` one; kept with every replace so the per-connection
    /// checks never walk the sets.
    uses_process: AtomicBool,
    uses_request: AtomicBool,
}

impl RuleSetStore {
    pub fn new(sets: BTreeMap<String, RuleSet>, remotes: Vec<RemoteRuleSet>) -> Self {
        Self::with_cache(sets, remotes, None)
    }

    /// As [`RuleSetStore::new`], keeping downloads in `cache` between runs:
    /// a remote set with a usable copy ([`RuleSetCache::load`]) starts with
    /// it instead of its inline entries, and copies no set uses are pruned
    /// ([`RuleSetCache::prune`]).
    pub fn with_cache(
        sets: BTreeMap<String, RuleSet>,
        remotes: Vec<RemoteRuleSet>,
        cache: Option<RuleSetCache>,
    ) -> Self {
        let mut sets: BTreeMap<String, Arc<RuleSet>> = sets
            .into_iter()
            .map(|(name, set)| (name, Arc::new(set)))
            .collect();
        for remote in &remotes {
            sets.entry(remote.name.clone()).or_default();
        }
        let status = sets
            .iter()
            .map(|(name, set)| {
                let remote = remotes.iter().find(|remote| &remote.name == name);
                let status = RuleSetStatus {
                    name: name.clone(),
                    source: if remote.is_some() { "remote" } else { "inline" },
                    entries: set.len(),
                    updated_at_ms: None,
                    last_error: None,
                    signed: remote.is_some_and(|remote| remote.signature.is_some()),
                    skipped: BTreeMap::new(),
                    from_cache: false,
                    cache_error: None,
                };
                (name.clone(), status)
            })
            .collect();
        // Not in the status list: nothing to download or count.
        sets.entry(LAN_RULE_SET.to_string())
            .or_insert_with(|| Arc::new(RuleSet::lan()));
        let store = Self {
            sets: RwLock::new(sets),
            remotes,
            cache,
            status: Mutex::new(status),
            refresh: Notify::new(),
            uses_process: AtomicBool::new(false),
            uses_request: AtomicBool::new(false),
        };
        if let Some(cache) = &store.cache {
            // One list at a time, so only one sits in memory as text.
            for remote in &store.remotes {
                if let Some(copy) = cache.load(remote) {
                    store.install(
                        &remote.name,
                        copy.set,
                        copy.skipped,
                        copy.fetched_at_ms,
                        true,
                    );
                }
            }
            cache.prune(&store.remotes);
        }
        store.update_uses(&store.read());
        store
    }

    /// Whether some set holds a `PROCESS-NAME` rule.
    pub fn uses_process(&self) -> bool {
        self.uses_process.load(Ordering::Relaxed)
    }

    /// Whether some set holds a `URL-REGEX` or `USER-AGENT` rule.
    pub fn uses_request(&self) -> bool {
        self.uses_request.load(Ordering::Relaxed)
    }

    fn update_uses(&self, sets: &BTreeMap<String, Arc<RuleSet>>) {
        self.uses_process.store(
            sets.values().any(|set| set.uses_process()),
            Ordering::Relaxed,
        );
        self.uses_request.store(
            sets.values().any(|set| set.uses_request()),
            Ordering::Relaxed,
        );
    }

    pub fn contains(&self, name: &str) -> bool {
        self.read().contains_key(name)
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, BTreeMap<String, Arc<RuleSet>>> {
        self.sets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn remotes(&self) -> &[RemoteRuleSet] {
        &self.remotes
    }

    /// Where downloads are kept between runs, when the config names a
    /// directory.
    pub fn cache(&self) -> Option<&RuleSetCache> {
        self.cache.as_ref()
    }

    /// How long after the updater starts it first downloads `remote`. With
    /// a cache directory: what is left of the interval since the kept copy
    /// was downloaded, nothing when there is no copy. Without one: nothing
    /// when the set starts empty, the whole interval when it starts with
    /// inline entries.
    pub fn first_update_delay(&self, remote: &RemoteRuleSet) -> Duration {
        let interval = Duration::from_secs(u64::from(remote.interval_secs));
        if self.cache.is_none() {
            return if self.is_empty_set(&remote.name) {
                Duration::ZERO
            } else {
                interval
            };
        }
        let kept_at = lock(&self.status)
            .get(&remote.name)
            .filter(|status| status.from_cache)
            .and_then(|status| status.updated_at_ms);
        kept_at.map_or(Duration::ZERO, |kept_at| {
            interval.saturating_sub(Duration::from_millis(unix_millis().saturating_sub(kept_at)))
        })
    }

    /// Every set with its entry count and download state, by name.
    pub fn status(&self) -> Vec<RuleSetStatus> {
        lock(&self.status).values().cloned().collect()
    }

    /// Asks the updater to download every remote set now; returns how many
    /// there are.
    pub fn refresh_now(&self) -> usize {
        if !self.remotes.is_empty() {
            self.refresh.notify_one();
        }
        self.remotes.len()
    }

    /// Completes when [`RuleSetStore::refresh_now`] was called.
    pub async fn refresh_requested(&self) {
        self.refresh.notified().await;
    }

    /// Installs a downloaded set for every later connection, with the
    /// lines its list held that it could not ([`RuleSetStatus::skipped`]).
    pub fn replace(&self, name: &str, set: RuleSet, skipped: BTreeMap<String, usize>) {
        self.install(name, set, skipped, unix_millis(), false);
    }

    /// As [`RuleSetStore::replace`] for a list downloaded at
    /// `fetched_at_ms`, with how keeping it in the cache directory went:
    /// `cache_error` says why it could not be kept, `None` when it was or
    /// there is no directory ([`RuleSetStatus::cache_error`]).
    pub fn replace_downloaded(
        &self,
        name: &str,
        set: RuleSet,
        skipped: BTreeMap<String, usize>,
        fetched_at_ms: u64,
        cache_error: Option<&'static str>,
    ) {
        self.install(name, set, skipped, fetched_at_ms, false);
        if let Some(status) = lock(&self.status).get_mut(name) {
            status.cache_error = cache_error;
        }
    }

    /// Puts `set` in force; `updated_at_ms` is when its list was
    /// downloaded, `from_cache` whether it is the kept copy of a download.
    fn install(
        &self,
        name: &str,
        set: RuleSet,
        skipped: BTreeMap<String, usize>,
        updated_at_ms: u64,
        from_cache: bool,
    ) {
        let entries = set.len();
        {
            let mut sets = self
                .sets
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sets.insert(name.to_string(), Arc::new(set));
            self.update_uses(&sets);
        }
        if let Some(status) = lock(&self.status).get_mut(name) {
            status.entries = entries;
            status.updated_at_ms = Some(updated_at_ms);
            status.last_error = None;
            status.skipped = skipped;
            status.from_cache = from_cache;
        }
    }

    pub fn record_failure(&self, name: &str, error: &'static str) {
        if let Some(status) = lock(&self.status).get_mut(name) {
            status.last_error = Some(error);
        }
    }

    pub fn is_empty_set(&self, name: &str) -> bool {
        self.read().get(name).is_none_or(|set| set.is_empty())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(all(test, feature = "local-proxy"))]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key_pair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
        pair.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn accepts_a_valid_signature_in_any_base64_shape() {
        let pair = key_pair();
        let body = b"DOMAIN-SUFFIX,example.com\n";
        let signature = pair.sign(body);
        let plain = STANDARD.encode(signature.as_ref());
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, plain.as_bytes()),
            Ok(())
        );
        let commented = format!(
            "untrusted comment: list\n\n{}\n",
            plain.trim_end_matches('=')
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, commented.as_bytes()),
            Ok(())
        );
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref());
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, url_safe.as_bytes()),
            Ok(())
        );
    }

    #[test]
    fn refuses_a_changed_list_another_key_and_junk() {
        let pair = key_pair();
        let body = b"DOMAIN-SUFFIX,example.com\n";
        let signature = STANDARD.encode(pair.sign(body).as_ref());
        assert_eq!(
            verify_list_signature(
                &public_key(&pair),
                b"DOMAIN-SUFFIX,evil.example\n",
                signature.as_bytes()
            ),
            Err("signature_invalid")
        );
        assert_eq!(
            verify_list_signature(&public_key(&key_pair()), body, signature.as_bytes()),
            Err("signature_invalid")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, b""),
            Err("signature_malformed")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, b"not base64!"),
            Err("signature_malformed")
        );
        let short = STANDARD.encode([0u8; 32]);
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, short.as_bytes()),
            Err("signature_malformed")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, &[0xff, 0xfe]),
            Err("signature_malformed")
        );
    }
}
