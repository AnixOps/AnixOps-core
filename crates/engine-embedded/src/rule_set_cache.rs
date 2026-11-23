//! Remote rule sets kept on disk between runs (`routing.rule_set_cache_dir`).
//!
//! The last good download of each remote set is one file in a directory the
//! client names, so after a restart the set starts from it instead of empty,
//! and keeps it while downloads fail. A file is written only after the list
//! passed every check a download must (the signature of a signed set, a
//! non-empty list within [`MAX_RULE_SET_ENTRIES`]): to a temporary file that
//! is synced and then renamed over the old copy, so a crash leaves the old
//! copy or the new one, never a mix.
//!
//! A file is named after a SHA-256 of what its content depends on: the URL
//! and, for a signed set, the public key and the signature URL. Never the set
//! name: names such as `local-1` follow the order of the client's rules, so
//! after an edit the same name can stand for another list. Neither a name nor
//! a file shows the URL, which may carry a subscription token.
//!
//! A file keeps the list's exact bytes and, for a signed set, its detached
//! signature, so loading checks the signature again with the key the config
//! names now:
//!
//! ```text
//! "ANXRSET" 0x01 | downloaded at (u64 BE, Unix ms) | signature length (u32 BE)
//! | list length (u32 BE) | SHA-256 of all the other bytes (32)
//! | signature | list
//! ```
//!
//! A copy that is damaged, too large, empty, or whose signature no longer
//! verifies is ignored: the set starts as it would without a cache and is
//! downloaded right away. Copies no configured set uses are deleted once
//! [`MAX_UNUSED_AGE`] old, or sooner, oldest first, while they take more than
//! [`MAX_UNUSED_BYTES`] together, so switching to another profile and back
//! keeps them. Nothing else in the directory is touched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use config_core::rule_set::{RuleSet, RuleSetBuilder, MAX_RULE_SET_ENTRIES};
use ring::digest::{Context, Digest, SHA256};

use crate::rule_sets::{RemoteRuleSet, MAX_LIST_BYTES, MAX_SIGNATURE_BYTES};

/// Why a download could not be kept: the directory cannot be created or
/// written. The download is installed all the same.
pub const WRITE_FAILED: &str = "cache_write_failed";
/// Copies no configured set uses are deleted once this old.
pub const MAX_UNUSED_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Most bytes the copies no configured set uses may take together.
pub const MAX_UNUSED_BYTES: u64 = 64 * 1024 * 1024;
/// A temporary file this old was left by a write that never finished.
const STALE_TEMP_AGE: Duration = Duration::from_secs(60 * 60);

const MAGIC: &[u8; 8] = b"ANXRSET\x01";
const EXTENSION: &str = "ruleset";
const TEMP_SUFFIX: &str = ".partial";
const DIGEST_LEN: usize = 32;
/// Magic, download time and both lengths: the part the digest follows.
const HEAD_LEN: usize = MAGIC.len() + 8 + 4 + 4;
const HEADER_LEN: usize = HEAD_LEN + DIGEST_LEN;
/// Largest file read back.
const MAX_FILE_BYTES: usize = HEADER_LEN + MAX_SIGNATURE_BYTES + MAX_LIST_BYTES;

/// The directory remote rule sets are kept in between runs.
#[derive(Clone, Debug)]
pub struct RuleSetCache {
    dir: PathBuf,
}

/// A remote set's kept copy, as [`RuleSetCache::load`] read it back.
pub struct CachedRuleSet {
    pub set: RuleSet,
    /// Lines of the list no set can hold, by rule type, as a download
    /// counts them.
    pub skipped: BTreeMap<String, usize>,
    /// Unix milliseconds of the download the copy comes from.
    pub fetched_at_ms: u64,
}

impl RuleSetCache {
    /// Touches nothing until a copy is loaded, written or pruned; the
    /// directory is created by the first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file `remote`'s copy is kept in.
    pub fn path(&self, remote: &RemoteRuleSet) -> PathBuf {
        self.dir.join(file_name(remote))
    }

    /// `remote`'s copy, when there is one that passes every check a
    /// download must, with the signature checked again against the key the
    /// config names now. Anything else is `None`, never an error: the set
    /// then starts as it would without a cache.
    pub fn load(&self, remote: &RemoteRuleSet) -> Option<CachedRuleSet> {
        let file = fs::File::open(self.path(remote)).ok()?;
        let len = file.metadata().ok()?.len();
        if len > MAX_FILE_BYTES as u64 {
            return None;
        }
        let mut bytes = Vec::with_capacity(len as usize);
        file.take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let (fetched_at_ms, signature, list) = decode(&bytes)?;
        if !signature_holds(remote, list, signature) {
            return None;
        }
        // As a download: straight into the compact tables, and the bytes go
        // before they are sorted and packed.
        let (builder, _) = {
            let text = String::from_utf8_lossy(list);
            RuleSetBuilder::parse_list(&text, remote.bare)
        };
        drop(bytes);
        if builder.is_empty() || builder.len() > MAX_RULE_SET_ENTRIES {
            return None;
        }
        let skipped = builder.skipped().clone();
        Some(CachedRuleSet {
            set: builder.build(),
            skipped,
            fetched_at_ms,
        })
    }

    /// Keeps `list`, downloaded at `fetched_at_ms`, as `remote`'s copy, with
    /// the detached `signature` a signed set's download came with. The old
    /// copy is replaced only once the new one is whole on disk; on any error
    /// ([`WRITE_FAILED`]) it stays as it was.
    pub fn store(
        &self,
        remote: &RemoteRuleSet,
        signature: Option<&[u8]>,
        list: &[u8],
        fetched_at_ms: u64,
    ) -> Result<(), &'static str> {
        let signature = signature.unwrap_or_default();
        if signature.len() > MAX_SIGNATURE_BYTES || list.len() > MAX_LIST_BYTES {
            return Err(WRITE_FAILED);
        }
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&fetched_at_ms.to_be_bytes());
        header.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        header.extend_from_slice(&(list.len() as u32).to_be_bytes());
        let digest = digest_of(&header, signature, list);
        header.extend_from_slice(digest.as_ref());

        let name = file_name(remote);
        let temp = self
            .dir
            .join(format!(".{name}.{}{TEMP_SUFFIX}", temp_tag()));
        let path = self.dir.join(name);
        fs::create_dir_all(&self.dir)
            .and_then(|()| {
                let mut file = fs::File::create(&temp)?;
                file.write_all(&header)?;
                file.write_all(signature)?;
                file.write_all(list)?;
                file.sync_all()
            })
            .and_then(|()| fs::rename(&temp, path))
            .map_err(|_| {
                let _ = fs::remove_file(&temp);
                WRITE_FAILED
            })
    }

    /// Deletes the copies no set of `remotes` uses once they are
    /// [`MAX_UNUSED_AGE`] old, then the oldest of the rest while they take
    /// more than [`MAX_UNUSED_BYTES`] together, and the temporary files of
    /// writes that never finished. Returns how many files went.
    pub fn prune(&self, remotes: &[RemoteRuleSet]) -> usize {
        self.prune_at(remotes, SystemTime::now(), MAX_UNUSED_AGE, MAX_UNUSED_BYTES)
    }

    fn prune_at(
        &self,
        remotes: &[RemoteRuleSet],
        now: SystemTime,
        max_age: Duration,
        max_bytes: u64,
    ) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let used: BTreeSet<String> = remotes.iter().map(file_name).collect();
        let mut removed = 0;
        let mut unused = Vec::new();
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            // A time in the future (the clock went back) counts as new.
            let age = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .unwrap_or_default();
            if is_temp_name(&name) {
                if age > STALE_TEMP_AGE && fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            } else if is_copy_name(&name) && !used.contains(&name) {
                if age <= max_age {
                    unused.push((age, metadata.len(), entry.path()));
                } else if fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        unused.sort_by_key(|(age, _, _)| std::cmp::Reverse(*age));
        let mut total: u64 = unused.iter().map(|(_, len, _)| len).sum();
        for (_, len, path) in unused {
            if total <= max_bytes {
                break;
            }
            if fs::remove_file(path).is_ok() {
                total -= len;
                removed += 1;
            }
        }
        removed
    }
}

/// `<64 hex>.ruleset`: SHA-256 of the URL and, for a signed set, the public
/// key and signature URL, each with its length so no two settings collide.
fn file_name(remote: &RemoteRuleSet) -> String {
    let mut context = Context::new(&SHA256);
    update_field(&mut context, b"networkcore rule set cache 1");
    update_field(&mut context, remote.url.as_bytes());
    if let Some(signature) = &remote.signature {
        update_field(&mut context, signature.public_key.as_slice());
        update_field(&mut context, signature.url.as_bytes());
    }
    format!("{}.{EXTENSION}", hex(context.finish().as_ref()))
}

fn update_field(context: &mut Context, bytes: &[u8]) {
    context.update(&(bytes.len() as u64).to_be_bytes());
    context.update(bytes);
}

/// SHA-256 of a file's head (magic, time, lengths), signature and list.
fn digest_of(head: &[u8], signature: &[u8], list: &[u8]) -> Digest {
    let mut context = Context::new(&SHA256);
    context.update(head);
    context.update(signature);
    context.update(list);
    context.finish()
}

/// The download time, signature and list of a whole cache file.
fn decode(file: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let head = file.get(..HEAD_LEN)?;
    if !head.starts_with(MAGIC) {
        return None;
    }
    let fetched_at_ms = u64::from_be_bytes(head[8..16].try_into().ok()?);
    let signature_len = usize::try_from(u32::from_be_bytes(head[16..20].try_into().ok()?)).ok()?;
    let list_len = usize::try_from(u32::from_be_bytes(head[20..24].try_into().ok()?)).ok()?;
    if signature_len > MAX_SIGNATURE_BYTES
        || list_len > MAX_LIST_BYTES
        || file.len() != HEADER_LEN + signature_len + list_len
    {
        return None;
    }
    let digest = file.get(HEAD_LEN..HEADER_LEN)?;
    let (signature, list) = file.get(HEADER_LEN..)?.split_at(signature_len);
    if digest_of(head, signature, list).as_ref() != digest {
        return None;
    }
    Some((fetched_at_ms, signature, list))
}

/// Whether `list` may stand for `remote`: always for an unsigned set; for a
/// signed one only with a signature that verifies with its public key.
#[cfg(feature = "local-proxy")]
fn signature_holds(remote: &RemoteRuleSet, list: &[u8], signature: &[u8]) -> bool {
    remote.signature.as_ref().is_none_or(|expected| {
        crate::rule_sets::verify_list_signature(&expected.public_key, list, signature).is_ok()
    })
}

/// Without the `local-proxy` feature no set is downloaded, so none is signed.
#[cfg(not(feature = "local-proxy"))]
fn signature_holds(remote: &RemoteRuleSet, _list: &[u8], _signature: &[u8]) -> bool {
    remote.signature.is_none()
}

/// A part of a temporary file's name no other write uses at the same time.
fn temp_tag() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Whether `name` is a copy's file name, `<64 hex>.ruleset`.
fn is_copy_name(name: &str) -> bool {
    name.strip_suffix(EXTENSION)
        .and_then(|stem| stem.strip_suffix('.'))
        .is_some_and(|key| {
            key.len() == 2 * DIGEST_LEN && key.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// Whether `name` is a temporary file of [`RuleSetCache::store`],
/// `.<copy name>.<tag>.partial`.
fn is_temp_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(TEMP_SUFFIX))
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(copy, _)| is_copy_name(copy))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_sets::RuleSetSignature;
    use config_core::rule_set::BareDomain;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "networkcore-rule-set-cache-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn remote(url: &str, public_key: Option<[u8; 32]>) -> RemoteRuleSet {
        RemoteRuleSet {
            name: "ads".to_string(),
            url: url.to_string(),
            interval_secs: 86_400,
            bare: BareDomain::Suffix,
            via: "DIRECT".to_string(),
            signature: public_key.map(|public_key| RuleSetSignature {
                public_key,
                url: format!("{url}.sig"),
            }),
        }
    }

    #[test]
    fn copies_round_trip_and_damaged_ones_are_ignored() {
        let dir = temp_dir("round-trip");
        let cache = RuleSetCache::new(&dir);
        let ads = remote("https://example.test/ads.list", None);
        assert!(cache.load(&ads).is_none());

        cache
            .store(
                &ads,
                None,
                b"DOMAIN-SUFFIX,ads.test\nUSER-AGENT,BadBot*\nSCRIPT,x\n",
                1_700_000_000_000,
            )
            .unwrap();
        let copy = cache.load(&ads).unwrap();
        assert_eq!(copy.fetched_at_ms, 1_700_000_000_000);
        assert_eq!(copy.set.len(), 2);
        assert!(copy.set.matches(Some("x.ads.test"), None));
        assert!(copy.set.uses_request());
        assert_eq!(copy.skipped.get("SCRIPT"), Some(&1));
        // The format is read again with the settings of the day.
        let exact = RemoteRuleSet {
            bare: BareDomain::Exact,
            ..ads.clone()
        };
        assert_eq!(cache.path(&exact), cache.path(&ads));

        // A newer copy replaces the old one and leaves no temporary file.
        cache
            .store(&ads, None, b"DOMAIN-SUFFIX,new.test\n", 1_700_000_000_001)
            .unwrap();
        let copy = cache.load(&ads).unwrap();
        assert!(copy.set.matches(Some("www.new.test"), None));
        assert!(!copy.set.matches(Some("x.ads.test"), None));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        // A changed byte, a cut, an extra byte, another file: ignored.
        let path = cache.path(&ads);
        let whole = fs::read(&path).unwrap();
        let mut flipped = whole.clone();
        *flipped.last_mut().unwrap() ^= 0x20;
        let mut longer = whole.clone();
        longer.push(b'\n');
        let cut = whole[..whole.len() - 1].to_vec();
        for damaged in [flipped, cut, longer, b"DOMAIN-SUFFIX,x.test\n".to_vec()] {
            fs::write(&path, damaged).unwrap();
            assert!(cache.load(&ads).is_none());
        }
        // Larger than any copy can be: not read at all.
        fs::File::create(&path)
            .unwrap()
            .set_len(MAX_FILE_BYTES as u64 + 1)
            .unwrap();
        assert!(cache.load(&ads).is_none());
        // A list without entries is no copy either.
        cache.store(&ads, None, b"# nothing\n", 1).unwrap();
        assert!(cache.load(&ads).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copies_follow_the_url_and_signature_not_the_set_name() {
        let ads = remote("https://example.test/ads.list", None);
        let renamed = RemoteRuleSet {
            name: "local-2".to_string(),
            interval_secs: 600,
            via: "Proxy".to_string(),
            ..ads.clone()
        };
        assert_eq!(file_name(&renamed), file_name(&ads));
        assert!(is_copy_name(&file_name(&ads)));
        assert_ne!(
            file_name(&remote("https://example.test/other.list", None)),
            file_name(&ads)
        );
        let signed = remote("https://example.test/ads.list", Some([1; 32]));
        assert_ne!(file_name(&signed), file_name(&ads));
        assert_ne!(
            file_name(&remote("https://example.test/ads.list", Some([2; 32]))),
            file_name(&signed)
        );
        let moved_signature = RemoteRuleSet {
            signature: Some(RuleSetSignature {
                public_key: [1; 32],
                url: "https://example.test/sig".to_string(),
            }),
            ..ads.clone()
        };
        assert_ne!(file_name(&moved_signature), file_name(&signed));
        // Nothing of the URL shows.
        assert!(!file_name(&ads).contains("example"));
        assert!(!is_copy_name("notes.txt"));
        assert!(is_temp_name(&format!(".{}.12-0.partial", file_name(&ads))));
        assert!(!is_temp_name(".notes.12-0.partial"));
    }

    #[test]
    fn unsigned_copies_never_stand_for_a_signed_set() {
        let dir = temp_dir("unsigned");
        let cache = RuleSetCache::new(&dir);
        let signed = remote("https://example.test/ads.list", Some([3; 32]));
        cache
            .store(&signed, None, b"DOMAIN-SUFFIX,ads.test\n", 1)
            .unwrap();
        assert!(cache.load(&signed).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "local-proxy")]
    #[test]
    fn signed_copies_load_only_while_the_signature_verifies() {
        use base64::Engine as _;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let public_key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let signed = remote("https://example.test/ads.list", Some(public_key));
        let list = b"DOMAIN-SUFFIX,ads.test\n";
        let signature = base64::engine::general_purpose::STANDARD.encode(pair.sign(list).as_ref());

        let dir = temp_dir("signed");
        let cache = RuleSetCache::new(&dir);
        cache
            .store(&signed, Some(signature.as_bytes()), list, 5)
            .unwrap();
        assert_eq!(cache.load(&signed).unwrap().fetched_at_ms, 5);
        // A list the signature is not over.
        cache
            .store(
                &signed,
                Some(signature.as_bytes()),
                b"DOMAIN-SUFFIX,other.test\n",
                6,
            )
            .unwrap();
        assert!(cache.load(&signed).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_to_an_unusable_directory_fail_cleanly() {
        let dir = temp_dir("unusable");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        fs::write(&file, b"not a directory").unwrap();
        let cache = RuleSetCache::new(file.join("cache"));
        let ads = remote("https://example.test/ads.list", None);
        assert_eq!(
            cache.store(&ads, None, b"DOMAIN-SUFFIX,ads.test\n", 1),
            Err(WRITE_FAILED)
        );
        assert!(cache.load(&ads).is_none());
        assert_eq!(cache.prune(&[]), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unused_copies_go_when_old_or_over_the_budget() {
        let dir = temp_dir("prune");
        let cache = RuleSetCache::new(&dir);
        let now = SystemTime::now();
        let days = |n: u64| Duration::from_secs(n * 24 * 60 * 60);
        let list = vec![b'#'; 1000];
        let aged = |remote: &RemoteRuleSet, age: Duration| {
            cache.store(remote, None, &list, 1).unwrap();
            fs::File::options()
                .write(true)
                .open(cache.path(remote))
                .unwrap()
                .set_modified(now - age)
                .unwrap();
        };
        let used = remote("https://example.test/used.list", None);
        let expired = remote("https://example.test/expired.list", None);
        let older = remote("https://example.test/older.list", None);
        let newer = remote("https://example.test/newer.list", None);
        aged(&used, days(400));
        aged(&expired, days(31));
        aged(&older, days(3));
        aged(&newer, days(1));
        let notes = dir.join("notes.txt");
        fs::write(&notes, b"not ours").unwrap();
        let stale = dir.join(format!(".{}.1-0{TEMP_SUFFIX}", file_name(&used)));
        let fresh = dir.join(format!(".{}.1-1{TEMP_SUFFIX}", file_name(&used)));
        fs::write(&stale, b"").unwrap();
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(now - days(1))
            .unwrap();
        fs::write(&fresh, b"").unwrap();

        // Room for one unused copy: the expired one and the older one go,
        // with the temporary file of a write that never finished; the copy
        // in use stays however old it is.
        let copy_len = fs::metadata(cache.path(&newer)).unwrap().len();
        let in_use = std::slice::from_ref(&used);
        assert_eq!(cache.prune_at(in_use, now, days(30), copy_len + 1), 3);
        assert!(cache.path(&used).exists());
        assert!(!cache.path(&expired).exists());
        assert!(!cache.path(&older).exists());
        assert!(cache.path(&newer).exists());
        assert!(notes.exists());
        assert!(!stale.exists());
        assert!(fresh.exists());
        // Two months later the last unused copy and that temporary file go.
        assert_eq!(
            cache.prune_at(in_use, now + days(60), days(30), u64::MAX),
            2
        );
        assert!(!cache.path(&newer).exists());
        assert!(!fresh.exists());
        assert!(cache.path(&used).exists());
        assert!(notes.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
