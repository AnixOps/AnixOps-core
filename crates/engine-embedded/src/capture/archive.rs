//! The `zip` export of `export_capture`: the whole capture (or one
//! connection) packed into one file the user can share, with what each
//! tool opens:
//!
//! | File | What it holds |
//! | --- | --- |
//! | `README.txt` | what is inside, when it was made, whether credentials are masked |
//! | `connections.json` | every captured connection: target, times, bytes each way, its requests (method, URL, status, sizes) |
//! | `capture.har` | the decrypted HTTP requests with their headers and bodies (HAR 1.2), when there are any |
//! | `capture.pcapng` | every connection's kept bytes as synthetic TCP/UDP flows, decrypted ones as HTTP/1.1 text |
//!
//! The archive is a plain ZIP (no ZIP64: the store never holds more than
//! [`super::MAX_TOTAL_BYTES_LIMIT`]), entries deflated, names in UTF-8.

use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};
use serde_json::{json, Value};

use super::{redacted, selected, CaptureStore, Captured};

/// The files of a capture archive, in the order they are written.
pub(super) fn capture_zip(
    store: &CaptureStore,
    id: Option<u64>,
    redact: bool,
    now_ms: u64,
) -> Vec<u8> {
    let (connections, requests) = summary(store, id, redact);
    let count = connections.len();
    let har = (requests > 0).then(|| store.export_har(id, redact));
    let pcapng = store.export_pcapng(id, redact);
    let listing = serde_json::to_vec_pretty(&json!({
        "generator": format!("AnixOps Net {}", env!("CARGO_PKG_VERSION")),
        "exported_at_ms": now_ms,
        "redacted": redact,
        "connections": connections,
    }))
    .unwrap_or_default();
    let readme = readme(count, requests, redact, har.is_some());
    let mut files: Vec<(&str, &[u8])> = vec![
        ("README.txt", readme.as_bytes()),
        ("connections.json", listing.as_slice()),
    ];
    if let Some(har) = &har {
        files.push(("capture.har", har.as_slice()));
    }
    files.push(("capture.pcapng", pcapng.as_slice()));
    zip(&files, now_ms)
}

/// `connections.json`'s list and how many requests it names.
fn summary(store: &CaptureStore, id: Option<u64>, redact: bool) -> (Vec<Value>, usize) {
    let inner = super::lock(&store.inner);
    let mut requests = 0;
    let connections = selected(&inner, id)
        .into_iter()
        .map(|(&id, captured)| {
            requests += captured.http.len();
            connection(id, captured, redact)
        })
        .collect();
    (connections, requests)
}

fn connection(id: u64, captured: &Captured, redact: bool) -> Value {
    let direction = |index: usize| {
        json!({
            "seen": captured.seen[index],
            "captured": captured.kept[index],
        })
    };
    json!({
        "id": id,
        "network": captured.network,
        "host": captured.host,
        "destination": captured.destination,
        "started_at_ms": captured.started_at_ms,
        "ended_at_ms": captured.ended_at_ms,
        "decrypted": captured.decrypted,
        "upload": direction(0),
        "download": direction(1),
        "requests": captured
            .http
            .iter()
            .enumerate()
            .map(|(position, exchange)| {
                let exchange = redacted(exchange, redact);
                json!({
                    "index": captured.http_base + position,
                    "http_version": exchange.http_version,
                    "method": exchange.method,
                    "url": exchange.url,
                    "status": exchange.status,
                    "started_at_ms": exchange.started_at_ms,
                    "ended_at_ms": exchange.ended_at_ms,
                    "request_body_size": exchange.request_body.size,
                    "response_body_size": exchange.response_body.size,
                    "note": exchange.note,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn readme(connections: usize, requests: usize, redact: bool, har: bool) -> String {
    let mut text = String::new();
    text.push_str("AnixOps Net capture / AnixOps Net 抓包\r\n\r\n");
    text.push_str(&format!(
        "{connections} connections, {requests} decrypted HTTP requests.\r\n{connections} 个连接，{requests} 个解密的 HTTP 请求。\r\n\r\n"
    ));
    text.push_str("connections.json  Every connection: target, times, bytes, its requests.\r\n");
    text.push_str("                  每个连接的目标、时间、流量和其中的请求。\r\n");
    if har {
        text.push_str("capture.har       Decrypted HTTP requests with headers and bodies. Open in browser developer tools, Charles or Proxyman.\r\n");
        text.push_str("                  解密的 HTTP 请求（含头和正文），可导入浏览器开发者工具、Charles 或 Proxyman。\r\n");
    }
    text.push_str("capture.pcapng    The kept bytes of every connection. Open in Wireshark.\r\n");
    text.push_str("                  每个连接保留的原始字节，用 Wireshark 打开。\r\n\r\n");
    if redact {
        text.push_str(
            "Passwords, tokens and cookies are masked.\r\n密码、令牌和 Cookie 已遮盖。\r\n",
        );
    } else {
        text.push_str("NOT masked: this file may hold passwords, tokens and cookies. Share it only with people you trust.\r\n");
        text.push_str("未遮盖：文件里可能有密码、令牌和 Cookie，请只发给信任的人。\r\n");
    }
    text
}

/// A ZIP archive of `files`, each deflated and dated `modified_ms` (UTC).
pub fn zip(files: &[(&str, &[u8])], modified_ms: u64) -> Vec<u8> {
    const VERSION: u16 = 20;
    /// Bit 11: names are UTF-8.
    const FLAGS: u16 = 1 << 11;
    const DEFLATE: u16 = 8;
    let (time, date) = dos_time(modified_ms);
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let mut crc = Crc::new();
        crc.update(data);
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        // Writing to a Vec cannot fail.
        let _ = encoder.write_all(data);
        let compressed = encoder.finish().unwrap_or_default();
        let offset = out.len() as u32;
        let name = name.as_bytes();
        let header = |signature: u32, out: &mut Vec<u8>, central: bool| {
            out.extend_from_slice(&signature.to_le_bytes());
            if central {
                out.extend_from_slice(&VERSION.to_le_bytes());
            }
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&FLAGS.to_le_bytes());
            out.extend_from_slice(&DEFLATE.to_le_bytes());
            out.extend_from_slice(&time.to_le_bytes());
            out.extend_from_slice(&date.to_le_bytes());
            out.extend_from_slice(&crc.sum().to_le_bytes());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            // No extra field.
            out.extend_from_slice(&0u16.to_le_bytes());
        };
        header(0x0403_4b50, &mut out, false);
        out.extend_from_slice(name);
        out.extend_from_slice(&compressed);

        header(0x0201_4b50, &mut central, true);
        // Comment length, disk number, internal and external attributes.
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let central_offset = out.len() as u32;
    let central_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    // This disk, the disk with the directory.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    // No archive comment.
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// MS-DOS time and date of `millis` (UTC), clamped to 1980.
fn dos_time(millis: u64) -> (u16, u16) {
    let seconds = millis / 1000;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil(days);
    if year < 1980 {
        return (0, (1 << 5) | 1);
    }
    let time = ((rest / 3600) << 11) | (((rest % 3600) / 60) << 5) | ((rest % 60) / 2);
    let date = (((year - 1980).min(127) as u64) << 9) | ((month as u64) << 5) | day as u64;
    (time as u16, date as u16)
}

/// Year, month and day of `days` since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
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

/// Reads an archive back with nothing but its own headers (tests).
#[cfg(test)]
pub(crate) fn unzip(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    use std::io::Read;

    let end = archive.len() - 22;
    assert_eq!(&archive[end..end + 4], &0x0605_4b50u32.to_le_bytes());
    let count = u16::from_le_bytes([archive[end + 10], archive[end + 11]]) as usize;
    let mut at = u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap()) as usize;
    let mut files = Vec::new();
    for _ in 0..count {
        assert_eq!(&archive[at..at + 4], &0x0201_4b50u32.to_le_bytes());
        let field = |offset: usize, len: usize| {
            let mut value = 0u64;
            for (shift, byte) in archive[at + offset..at + offset + len].iter().enumerate() {
                value |= u64::from(*byte) << (8 * shift);
            }
            value
        };
        let crc = field(16, 4) as u32;
        let compressed = field(20, 4) as usize;
        let size = field(24, 4) as usize;
        let name_len = field(28, 2) as usize;
        let local = field(42, 4) as usize;
        let name = String::from_utf8(archive[at + 46..at + 46 + name_len].to_vec()).unwrap();
        let local_name = u16::from_le_bytes([archive[local + 26], archive[local + 27]]) as usize;
        let data_at = local + 30 + local_name;
        let mut data = Vec::new();
        flate2::read::DeflateDecoder::new(&archive[data_at..data_at + compressed])
            .read_to_end(&mut data)
            .unwrap();
        assert_eq!(data.len(), size);
        let mut check = Crc::new();
        check.update(&data);
        assert_eq!(check.sum(), crc, "{name}");
        files.push((name, data));
        at += 46 + name_len;
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_holds_every_file_as_given() {
        let big = "抓包 capture ".repeat(5000);
        let archive = zip(
            &[
                ("README.txt", &b"hello"[..]),
                ("dir/中文.json", big.as_bytes()),
                ("empty", &b""[..]),
            ],
            1_700_000_000_000,
        );
        let files = unzip(&archive);
        assert_eq!(files.len(), 3);
        assert_eq!(files[0], ("README.txt".to_string(), b"hello".to_vec()));
        assert_eq!(files[1].0, "dir/中文.json");
        assert_eq!(files[1].1, big.as_bytes());
        assert!(files[2].1.is_empty());
        // Deflated: far smaller than the repeated text.
        assert!(archive.len() < big.len() / 10);
    }

    #[test]
    fn dos_time_is_utc_calendar_time() {
        // 2023-11-14 22:13:20 UTC.
        let (time, date) = dos_time(1_700_000_000_000);
        assert_eq!(date >> 9, 2023 - 1980);
        assert_eq!((date >> 5) & 0xf, 11);
        assert_eq!(date & 0x1f, 14);
        assert_eq!(time >> 11, 22);
        assert_eq!((time >> 5) & 0x3f, 13);
        assert_eq!((time & 0x1f) * 2, 20);
        assert_eq!(dos_time(0), (0, (1 << 5) | 1));
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }

    #[test]
    fn capture_zip_lists_connections_and_skips_har_without_requests() {
        let store = CaptureStore::default();
        let archive = capture_zip(&store, None, true, 1_700_000_000_000);
        let files = unzip(&archive);
        let names: Vec<_> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["README.txt", "connections.json", "capture.pcapng"]);
        let listing: Value = serde_json::from_slice(&files[1].1).unwrap();
        assert_eq!(listing["redacted"], true);
        assert_eq!(listing["connections"], json!([]));
        assert!(String::from_utf8_lossy(&files[0].1).contains("masked"));
    }
}
