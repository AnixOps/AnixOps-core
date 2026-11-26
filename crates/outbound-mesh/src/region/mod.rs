//! Region auto-assignment and region changes (spec §15.8, appendix D),
//! without I/O.
//!
//! - [`directory`]: the region directory and the `PUT /v1/mesh` top-level
//!   `region` object (D.2.2, D.9.1).
//! - [`probe`]: the authenticated probe packet, the node's prober and the
//!   border node's responder (D.3).
//! - [`measure`]: one measurement round and the first choice of a region
//!   (D.4, D.5).
//! - [`suggest`]: re-measurement history and the region change suggestion
//!   (D.6).
//! - [`round`] (feature `runtime`): one measurement round over UDP.

pub mod directory;
pub mod measure;
pub mod probe;
#[cfg(feature = "runtime")]
pub mod round;
pub mod suggest;

/// RFC 3339 UTC text of Unix seconds, `1970-01-01T00:00:00Z` style.
pub fn rfc3339(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let rest = unix_secs % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_764_126_000), "2025-11-26T03:00:00Z");
        assert_eq!(rfc3339(4_107_542_399), "2100-02-28T23:59:59Z");
    }
}
