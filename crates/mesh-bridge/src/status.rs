//! What the status API reports about a bridge: `networks[].externalBridge`
//! (`docs/architecture/mesh-status.md`). The panel computes the same
//! digests over the lists it sent; equal digests mean the bridge applied
//! them (spec §15.12 item 4, address reuse order).

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use outbound_mesh::IpNet;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The applied bridge of one network. `None` in the status (JSON `null`)
/// when the network has no bridge, or its rules were removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    pub allow_digest: String,
    pub allow_count: usize,
    pub routes_digest: String,
    /// RFC 3339, UTC, whole seconds.
    pub applied_at: String,
}

/// The digest of a list: each entry as normalised CIDR text, duplicates
/// removed, sorted by bytes, joined with `\n` (no trailing newline), then
/// SHA-256 in lower-case hex.
pub fn digest(nets: &[IpNet]) -> String {
    let mut lines: Vec<String> = nets.iter().map(|net| net.trunc().to_string()).collect();
    lines.sort();
    lines.dedup();
    let hash = Sha256::digest(lines.join("\n").as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in hash.iter() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Number of distinct entries, the `allowCount` the panel compares.
pub fn count(nets: &[IpNet]) -> usize {
    let mut lines: Vec<String> = nets.iter().map(|net| net.trunc().to_string()).collect();
    lines.sort();
    lines.dedup();
    lines.len()
}

impl BridgeStatus {
    pub fn new(routes: &[IpNet], allow: &[IpNet], at: SystemTime) -> Self {
        Self {
            allow_digest: digest(allow),
            allow_count: count(allow),
            routes_digest: digest(routes),
            applied_at: rfc3339(at),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`. Times before 1970 print as the epoch.
pub fn rfc3339(at: SystemTime) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| IpNet::parse(s).unwrap()).collect()
    }

    /// The shared vectors of `docs/architecture/mesh-status.md`.
    #[test]
    fn the_spec_vectors_match() {
        let vectors: [(&[&str], &str, usize); 5] = [
            (
                &[],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                0,
            ),
            (
                &["10.0.0.5"],
                "65078d8a7bd32b6934150b573cfa67ab5eace9b47601e86deb978ac3be4ba6fc",
                1,
            ),
            (
                &["10.0.0.5/32", "192.168.1.0/24", "10.0.0.5"],
                "f8eb52bad06ba0dc556b78371a449a2fea20c61b8810fff1fff7fc5877065d06",
                2,
            ),
            (
                &[
                    "FD7A:115C:A1E0:0:0:0:0:1",
                    "10.150.0.7/32",
                    "fd7a:115c:a1e0::1/128",
                    "192.168.10.0/24",
                    "FD00:AA:0:0::/64",
                ],
                "f4843004a47d48528d070b5e98e8526e14e22a0b73c7b907f2622f0c009e947b",
                4,
            ),
            (
                &[
                    "10.150.0.2/32",
                    "10.127.0.0/24",
                    "fd7a:115c:a1e0::5/128",
                    "10.150.0.128/32",
                ],
                "c2125301582f23d00252ec7ea3ae881359c66f9333fcae94ba95c64931257366",
                4,
            ),
        ];
        for (input, expected, n) in vectors {
            assert_eq!(digest(&nets(input)), expected, "{input:?}");
            assert_eq!(count(&nets(input)), n, "{input:?}");
        }
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let at = UNIX_EPOCH + Duration::from_secs(1_795_641_019);
        assert_eq!(rfc3339(at), "2026-11-25T21:10:19Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn the_status_serialises_in_camel_case() {
        let status = BridgeStatus::new(&nets(&["100.64.0.1"]), &nets(&["10.0.0.5"]), UNIX_EPOCH);
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["allowCount"], 1);
        assert_eq!(
            json["allowDigest"],
            "65078d8a7bd32b6934150b573cfa67ab5eace9b47601e86deb978ac3be4ba6fc"
        );
        assert_eq!(json["appliedAt"], "1970-01-01T00:00:00Z");
        assert!(json.get("routesDigest").is_some());
    }
}
