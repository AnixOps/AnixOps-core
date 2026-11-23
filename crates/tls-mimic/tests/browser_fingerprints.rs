//! Each fingerprint against its target: a ClientHello captured from the real
//! browser must have the same JA4 and sorted-extension JA3 (JA3N) as the one
//! this crate builds for the same server name and ALPN, the same JA3 when the
//! browser does not permute its extensions, and the same X25519 key in its
//! X25519MLKEM768 and X25519 key shares exactly when the browser has one key
//! for both (`Hello::hybrid_x25519`, which JA3 and JA4 do not see). Neither
//! sees the ECH GREASE extension's insides either, so its AEAD and payload
//! length must be ones the profile's rule produces for that ClientHello (the
//! same length when the rule is not a random draw), our encapsulated key must
//! be an X25519 public key, and when no part of the ClientHello's length is
//! drawn at random its whole length must equal the browser's.
//!
//! Committed captures (`tests/data/<profile>-<version>.hex`) are checked on
//! every run. `captured_browsers_match_profiles` checks fresh ones from
//! `.github/workflows/browser-fingerprints.yml` (`TLS_MIMIC_CAPTURES`, one
//! `<profile>.hex` per browser) and prints a profile for any that differ.

use std::fmt::Write as _;
use std::path::Path;

use tls_mimic::fingerprint::{
    build_from_spec, EchGreaseShape, EchPayloadLength, Extension, HybridX25519,
};
use tls_mimic::ja::{
    decode_hex, is_x25519_public_key, parse_client_hello, spec_from_hello, EchOuter, Hello,
};
use tls_mimic::{ClientHelloSpec, Fingerprint};

struct Row {
    profile: &'static str,
    source: String,
    target: Hello,
    ours: Hello,
    permuted: bool,
    /// The profile's ECH GREASE shape, `None` when it sends none.
    ech: Option<EchGreaseShape>,
    /// Handshake message lengths, and whether ours is the same on every
    /// connection (no ECH payload length drawn at random).
    target_len: usize,
    ours_len: usize,
    fixed_len: bool,
}

impl Row {
    fn matches(&self) -> bool {
        self.target.ja4() == self.ours.ja4()
            && self.target.ja3n() == self.ours.ja3n()
            && (self.permuted || self.target.ja3() == self.ours.ja3())
            && self.target.hybrid_x25519() == self.ours.hybrid_x25519()
            && self.ech_matches()
            && (!self.fixed_len || self.target_len == self.ours_len)
    }

    /// The browser's ECH GREASE is one the profile could have sent for the
    /// same ClientHello, and ours has an X25519 public key as its
    /// encapsulated key.
    fn ech_matches(&self) -> bool {
        match (self.target.ech_outer(), self.ours.ech_outer(), &self.ech) {
            (None, None, None) => true,
            (Some(target), Some(ours), Some(shape)) => {
                target.kdf == ours.kdf
                    && target.enc.len() == ours.enc.len()
                    && is_x25519_public_key(&ours.enc)
                    && shape.aeads.contains(&target.aead)
                    && match &shape.payload_length {
                        EchPayloadLength::Drawn(lengths) => lengths.contains(&target.payload_len),
                        EchPayloadLength::PaddedInner { .. } => {
                            target.payload_len == ours.payload_len
                        }
                    }
            }
            _ => false,
        }
    }
}

/// ECH GREASE for the report: payload length and AEAD.
fn ech(hello: &Hello) -> String {
    match hello.ech_outer() {
        Some(EchOuter {
            payload_len, aead, ..
        }) => format!("{payload_len} / {aead:#06x}"),
        None => "-".to_owned(),
    }
}

/// Length of the handshake message in a capture given as a handshake
/// message or as TLS records (the first record starts the message).
fn message_len(bytes: &[u8]) -> usize {
    let header = if bytes.first() == Some(&0x16) {
        &bytes[5..9]
    } else {
        &bytes[..4]
    };
    4 + ((usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]))
}

fn ech_grease_of(spec: &ClientHelloSpec) -> Option<EchGreaseShape> {
    spec.extensions
        .iter()
        .find_map(|extension| match extension {
            Extension::EchGrease(shape) => Some(shape.clone()),
            _ => None,
        })
}

/// How a ClientHello's X25519MLKEM768 share gets its X25519 key, for the report.
fn hybrid_x25519(hello: &Hello) -> &'static str {
    match hello.hybrid_x25519() {
        Some(HybridX25519::Separate) => "separate",
        Some(HybridX25519::Shared) => "shared",
        None => "-",
    }
}

/// The fingerprint a capture file is for: the longest profile name it
/// starts with.
fn profile_of(file_stem: &str) -> Option<Fingerprint> {
    Fingerprint::ALL
        .into_iter()
        .filter(|fingerprint| {
            let name = fingerprint.name();
            file_stem == name || file_stem.starts_with(&format!("{name}-"))
        })
        .max_by_key(|fingerprint| fingerprint.name().len())
}

fn compare(fingerprint: Fingerprint, source: String, capture: &str) -> Row {
    let bytes = decode_hex(capture).unwrap();
    let target = parse_client_hello(&bytes).unwrap();
    let spec = fingerprint.spec().unwrap();
    let server_name = target.server_name().unwrap_or_default();
    let alpn = target.alpn();
    let built = build_from_spec(&spec, &server_name, Some(&alpn)).unwrap();
    let ech = ech_grease_of(&spec);
    let fixed_len = !matches!(
        ech,
        Some(EchGreaseShape {
            payload_length: EchPayloadLength::Drawn(_),
            ..
        })
    );
    Row {
        profile: fingerprint.name(),
        source,
        target,
        ours: parse_client_hello(&built.message).unwrap(),
        permuted: spec.permute_extensions,
        ech,
        target_len: message_len(&bytes),
        ours_len: built.message.len(),
        fixed_len,
    }
}

fn report(rows: &[Row]) -> String {
    let mut out = String::from(
        "| profile | capture | JA4 (browser) | JA4 (ours) | JA3N (browser) | JA3N (ours) | JA3 (browser) | JA3 (ours) | hybrid X25519 (browser) | hybrid X25519 (ours) | ECH length / AEAD (browser) | ECH length / AEAD (ours) | length (browser) | length (ours) | result |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for row in rows {
        let ja3 = |hello: &Hello| {
            if row.permuted {
                "permuted".to_owned()
            } else {
                hello.ja3()
            }
        };
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |",
            row.profile,
            row.source,
            row.target.ja4(),
            row.ours.ja4(),
            row.target.ja3n(),
            row.ours.ja3n(),
            ja3(&row.target),
            ja3(&row.ours),
            hybrid_x25519(&row.target),
            hybrid_x25519(&row.ours),
            ech(&row.target),
            ech(&row.ours),
            row.target_len,
            if row.fixed_len {
                row.ours_len.to_string()
            } else {
                format!("{} (drawn ECH)", row.ours_len)
            },
            if row.matches() {
                "match"
            } else {
                "**differs**"
            },
        );
    }
    out
}

fn check(rows: Vec<Row>) {
    let table = report(&rows);
    println!("{table}");
    if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
        let mut text = std::fs::read_to_string(&summary).unwrap_or_default();
        text.push_str("\n### tls-mimic fingerprints vs captured browsers\n\n");
        text.push_str(&table);
        let _ = std::fs::write(&summary, text);
    }
    let mut failed = Vec::new();
    for row in &rows {
        if row.matches() {
            continue;
        }
        println!("--- {} ({}) differs", row.profile, row.source);
        println!("browser ja3: {}", row.target.ja3_string());
        println!("ours    ja3: {}", row.ours.ja3_string());
        println!(
            "hybrid X25519 key: browser {}, ours {}",
            hybrid_x25519(&row.target),
            hybrid_x25519(&row.ours)
        );
        println!(
            "ECH GREASE (length / AEAD): browser {}, ours {}; profile {:?}; ours an X25519 key: {}",
            ech(&row.target),
            ech(&row.ours),
            row.ech,
            row.ours
                .ech_outer()
                .is_some_and(|ours| is_x25519_public_key(&ours.enc))
        );
        println!(
            "ClientHello length: browser {}, ours {}{}",
            row.target_len,
            row.ours_len,
            if row.fixed_len {
                ""
            } else {
                " (drawn ECH length)"
            }
        );
        match spec_from_hello(&row.target, row.permuted) {
            Ok(spec) => println!("profile from the capture: {}", spec.to_json()),
            Err(error) => println!("the capture cannot be reproduced by this build: {error}"),
        }
        failed.push(format!("{} ({})", row.profile, row.source));
    }
    assert!(failed.is_empty(), "fingerprints differ: {failed:?}");
}

fn captures_in(dir: &Path, require_profile: bool) -> Vec<Row> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
        .collect();
    entries.sort();
    let mut rows = Vec::new();
    for path in entries {
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let fingerprint = match profile_of(&stem) {
            Some(fingerprint) => fingerprint,
            None if require_profile => panic!("{stem}: no fingerprint of that name"),
            None => {
                // A browser without a profile yet: print what one would be.
                let capture = std::fs::read_to_string(&path).unwrap();
                let hello = parse_client_hello(&decode_hex(&capture).unwrap()).unwrap();
                println!("--- {stem} has no profile; ja4 {}", hello.ja4());
                match spec_from_hello(&hello, false) {
                    Ok(spec) => println!("profile from the capture: {}", spec.to_json()),
                    Err(error) => println!("cannot be reproduced by this build: {error}"),
                }
                continue;
            }
        };
        let capture = std::fs::read_to_string(&path).unwrap();
        rows.push(compare(fingerprint, stem, &capture));
    }
    rows
}

#[test]
fn committed_captures_match_their_profiles() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let rows = captures_in(&dir, true);
    assert!(!rows.is_empty());
    check(rows);
}

fn hybrid_x25519_of(spec: &ClientHelloSpec) -> HybridX25519 {
    spec.extensions
        .iter()
        .find_map(|extension| match extension {
            Extension::KeyShare { hybrid_x25519, .. } => Some(*hybrid_x25519),
            _ => None,
        })
        .expect("every profile has a key_share")
}

/// A profile derived from a capture keeps whether the browser reuses its
/// X25519 key in the hybrid share, so the profile the workflow prints for a
/// browser that moved reproduces that as well.
#[test]
fn profiles_derived_from_committed_captures_keep_the_hybrid_x25519_key() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let rows = captures_in(&dir, true);
    assert!(!rows.is_empty());
    for row in rows {
        let derived = hybrid_x25519_of(&spec_from_hello(&row.target, row.permuted).unwrap());
        let profile = Fingerprint::from_name(row.profile).unwrap().spec().unwrap();
        assert_eq!(
            derived,
            row.target.hybrid_x25519().unwrap_or_default(),
            "{}",
            row.source
        );
        assert_eq!(derived, hybrid_x25519_of(&profile), "{}", row.source);
    }
}

/// A profile derived from a capture keeps the ECH GREASE payload rule that
/// explains the capture: drawn for Chrome and Edge, the padded inner hello
/// with the RFC 9849 rounding for Firefox 160 and the older one for Firefox
/// 153 ESR. So the profile the workflow prints for a browser that moved
/// keeps it as well.
#[test]
fn profiles_derived_from_committed_captures_keep_the_ech_payload_rule() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let rows = captures_in(&dir, true);
    let mut with_ech = 0;
    for row in rows {
        let derived = ech_grease_of(&spec_from_hello(&row.target, row.permuted).unwrap());
        let profile = ech_grease_of(&Fingerprint::from_name(row.profile).unwrap().spec().unwrap());
        assert_eq!(
            derived.as_ref().map(|shape| &shape.payload_length),
            profile.as_ref().map(|shape| &shape.payload_length),
            "{}",
            row.source
        );
        if let (Some(derived), Some(ech)) = (&derived, row.target.ech_outer()) {
            assert_eq!(derived.aeads, [ech.aead], "{}", row.source);
            with_ech += 1;
        }
    }
    assert!(with_ech >= 4, "{with_ech}");
}

#[test]
#[ignore = "needs TLS_MIMIC_CAPTURES from the browser-fingerprints workflow"]
fn captured_browsers_match_profiles() {
    let dir = std::env::var("TLS_MIMIC_CAPTURES").expect("TLS_MIMIC_CAPTURES");
    let rows = captures_in(Path::new(&dir), false);
    check(rows);
}
