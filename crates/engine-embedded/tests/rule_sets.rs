//! Rule sets from the config: GEOSITE/GEOIP lists, port rules, and remote
//! lists the engine downloads itself.

use std::sync::Arc;

use config_core::routing::{RejectKind, RouteOutcome};
use engine_embedded::config::RuntimeConfig;
use engine_embedded::protocols::default_registry;
use engine_embedded::routing::RoutedOutbound;
use engine_outbound::{TargetAddr, TcpDialer};

fn routed(rules: &str, rule_sets: &str) -> Result<Arc<RoutedOutbound>, String> {
    routed_with(rules, rule_sets, "")
}

/// As [`routed`], with `extra` (`,"key":value` members) in the routing
/// section.
fn routed_with(rules: &str, rule_sets: &str, extra: &str) -> Result<Arc<RoutedOutbound>, String> {
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"p","routing":{{"outbounds":{{"hk":{{"type":"direct"}}}},"rules":[{rules}],"rule_sets":{{{rule_sets}}}{extra}}}}}"#
    );
    let config = RuntimeConfig::from_json(config.as_bytes()).map_err(|err| err.to_string())?;
    config
        .build_routed(&default_registry(), Arc::new(TcpDialer))
        .map_err(|err| err.to_string())
        .map(|routed| routed.expect("a routing config"))
}

/// The `rule_set_cache_dir` member naming `dir`, escaped for JSON (Windows
/// paths carry backslashes).
fn cache_dir_member(dir: &std::path::Path) -> String {
    let dir = serde_json::to_string(dir.to_str().unwrap()).unwrap();
    format!(r#","rule_set_cache_dir":{dir}"#)
}

fn domain(name: &str, port: u16) -> TargetAddr {
    TargetAddr::Domain(name.to_string(), port)
}

fn ip(addr: &str) -> TargetAddr {
    TargetAddr::Ip(addr.parse().unwrap())
}

#[test]
fn geosite_and_geoip_rules_match_their_sets() {
    let routed = routed(
        r#""GEOSITE,google,hk","GEOIP,CN,DIRECT,no-resolve","DST-PORT,22,REJECT","FINAL,hk""#,
        r#""geosite-google":{"domain_suffix":["google.com"],"domain":["g.co"]},"geoip-cn":{"ip_cidr":["1.0.1.0/24"]}"#,
    )
    .unwrap();
    let hk = RouteOutcome::Node("hk".to_string());
    assert_eq!(routed.route(&domain("mail.google.com", 443)), hk);
    assert_eq!(routed.route(&domain("g.co", 443)), hk);
    assert_eq!(routed.route(&ip("1.0.1.7:443")), RouteOutcome::Direct);
    assert_eq!(
        routed.route(&ip("1.0.2.7:22")),
        RouteOutcome::Reject(RejectKind::Reject)
    );
    assert_eq!(routed.route(&ip("1.0.2.7:443")), hk);

    let status = routed.rule_sets().status();
    assert_eq!(status.len(), 2);
    assert_eq!(status[0].name, "geoip-cn");
    assert_eq!(status[0].source, "inline");
    assert_eq!(status[1].entries, 2);
}

#[test]
fn the_built_in_lan_set_is_there_unless_the_config_names_one() {
    let routed = routed(r#""RULE-SET,LAN,DIRECT,no-resolve","FINAL,hk""#, "").unwrap();
    assert_eq!(routed.route(&ip("192.168.1.20:445")), RouteOutcome::Direct);
    assert_eq!(routed.route(&ip("[fe80::1]:445")), RouteOutcome::Direct);
    assert_eq!(
        routed.route(&domain("nas.local", 445)),
        RouteOutcome::Direct
    );
    assert_eq!(
        routed.route(&ip("8.8.8.8:53")),
        RouteOutcome::Node("hk".to_string())
    );
    // Built in, so not in the list of configured sets.
    assert!(routed.rule_sets().status().is_empty());

    let routed = routed_lan_override();
    assert_eq!(
        routed.route(&ip("192.168.1.20:445")),
        RouteOutcome::Node("hk".to_string())
    );
    assert_eq!(routed.route(&ip("192.0.2.1:445")), RouteOutcome::Direct);
}

#[test]
fn ip_asn_rules_use_asn_sets_and_missing_data_is_listed() {
    let asn = routed(
        r#""IP-ASN,13335,DIRECT,no-resolve","IP-ASN,64500,REJECT,no-resolve","GEOIP,US,REJECT,no-resolve","GEOIP,CN,DIRECT,no-resolve","FINAL,hk""#,
        r#""asn-13335":{"ip_cidr":["203.0.113.0/24"]},"geoip-cn":{"ip_cidr":["1.0.1.0/24"]}"#,
    )
    .unwrap();
    assert_eq!(asn.route(&ip("203.0.113.7:443")), RouteOutcome::Direct);
    assert_eq!(asn.route(&ip("1.0.1.9:443")), RouteOutcome::Direct);
    // AS 64500 and US have no data: they never match, and say so.
    assert_eq!(
        asn.route(&ip("198.51.100.7:443")),
        RouteOutcome::Node("hk".to_string())
    );
    assert_eq!(asn.missing_data_sets(), ["asn-64500", "geoip-us"]);

    let complete = routed(
        r#""GEOIP,CN,DIRECT","FINAL,hk""#,
        r#""geoip-cn":{"ip_cidr":["1.0.1.0/24"]}"#,
    )
    .unwrap();
    assert!(complete.missing_data_sets().is_empty());
}

fn routed_lan_override() -> Arc<RoutedOutbound> {
    routed(
        r#""RULE-SET,LAN,DIRECT,no-resolve","FINAL,hk""#,
        r#""LAN":{"ip_cidr":["192.0.2.0/24"]}"#,
    )
    .unwrap()
}

#[test]
fn rules_naming_missing_or_bad_sets_are_rejected() {
    assert!(routed(r#""GEOSITE,google,hk","FINAL,hk""#, "").is_err());
    assert!(routed(
        r#""AND,((RULE-SET,ads),(DST-PORT,443)),REJECT","FINAL,hk""#,
        ""
    )
    .is_err());
    // GEOIP without a list never matches, as before.
    assert!(routed(r#""GEOIP,CN,DIRECT","FINAL,hk""#, "").is_ok());
    for set in [
        r#""ads":{"url":"ftp://example.test/list"}"#,
        r#""ads":{"url":"https://example.test/list","interval_secs":60}"#,
        r#""ads":{"url":"https://example.test/list","format":"yaml"}"#,
        r#""ads":{"url":"https://example.test/list","via":"REJECT"}"#,
        r#""ads":{"url":"https://example.test/list","via":"missing"}"#,
        r#""ads":{"interval_secs":3600}"#,
        r#""ads":{"public_key":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}"#,
        r#""ads":{"domain":["bad name"]}"#,
    ] {
        assert!(
            routed(r#""RULE-SET,ads,REJECT","FINAL,hk""#, set).is_err(),
            "{set}"
        );
    }
}

#[test]
fn the_rule_set_cache_dir_must_be_an_absolute_path() {
    for dir in [r#""relative/rule-sets""#, r#""""#] {
        let member = format!(r#","rule_set_cache_dir":{dir}"#);
        assert!(routed_with(r#""FINAL,hk""#, "", &member).is_err(), "{dir}");
    }
    // Without remote sets nothing is read or written there.
    let dir = std::env::temp_dir().join(format!(
        "networkcore-rule-set-cache-unused-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let routed = routed_with(r#""FINAL,hk""#, "", &cache_dir_member(&dir)).unwrap();
    assert!(routed.rule_sets().status().is_empty());
    assert!(!dir.exists());
}

#[cfg(feature = "local-proxy")]
mod remote {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Serves `body` to every request and counts them.
    fn list_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ads.list", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (url, hits)
    }

    /// Serves `body` while the flag holds and `404` once it is cleared;
    /// counts the requests.
    fn switchable_server(body: &'static str) -> (String, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let up = Arc::new(AtomicBool::new(true));
        let (counter, serving) = (hits.clone(), up.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = if serving.load(Ordering::SeqCst) {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (url, hits, up)
    }

    fn wait_until(mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Runs the updater of `routed` on a runtime of its own; with nothing
    /// due it waits for the interval or a refresh.
    fn updating(routed: &Arc<RoutedOutbound>) -> tokio::runtime::Runtime {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        runtime
    }

    /// A fresh directory for one test's cache.
    fn cache_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "networkcore-rule-set-cache-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The copies kept in `dir`, temporary files of a write left out.
    fn kept_copies(dir: &Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .flatten()
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "ruleset")
                })
                .count()
        })
    }

    /// One remote set `ads` (`RULE-SET,ads,REJECT`) downloaded from `url`
    /// and kept in `dir`.
    fn cached_ads(url: &str, dir: &Path) -> Arc<RoutedOutbound> {
        routed_with(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}"}}"#),
            &cache_dir_member(dir),
        )
        .unwrap()
    }

    fn rejected() -> RouteOutcome {
        RouteOutcome::Reject(RejectKind::Reject)
    }

    fn proxied() -> RouteOutcome {
        RouteOutcome::Node("hk".to_string())
    }

    #[test]
    fn remote_sets_download_and_refresh_on_request() {
        let (url, hits) = list_server("payload:\n  - DOMAIN-SUFFIX,ads.test\n  - '+.track.test'\n");
        let routed = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}","format":"domain"}}"#),
        )
        .unwrap();
        // Before the first download the set is empty.
        assert_eq!(
            routed.route(&domain("x.ads.test", 443)),
            RouteOutcome::Node("hk".to_string())
        );

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        wait_until(|| routed.rule_sets().status()[0].updated_at_ms.is_some());
        let status = &routed.rule_sets().status()[0];
        assert_eq!(status.source, "remote");
        assert_eq!(status.entries, 2);
        assert_eq!(status.last_error, None);
        // Without a cache directory nothing is kept.
        assert!(!status.from_cache);
        assert_eq!(status.cache_error, None);
        assert!(routed.rule_sets().cache().is_none());
        assert_eq!(
            routed.route(&domain("x.ads.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        assert_eq!(
            routed.route(&domain("a.track.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        assert_eq!(routed.rule_sets().refresh_now(), 1);
        wait_until(|| hits.load(Ordering::SeqCst) == 2);
        runtime.shutdown_background();
    }

    #[test]
    fn downloads_keep_other_rule_types_and_count_what_no_set_holds() {
        let (url, _) = list_server(
            "DOMAIN-SUFFIX,ads.test\nUSER-AGENT,BadBot*\nIP-ASN,13335\nIP-ASN,15169\nSCRIPT,x\n",
        );
        let routed = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}"}}"#),
        )
        .unwrap();
        assert!(!routed.uses_request());

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        wait_until(|| routed.rule_sets().status()[0].updated_at_ms.is_some());
        let status = &routed.rule_sets().status()[0];
        // The domain, USER-AGENT and both IP-ASN lines; SCRIPT cannot be held.
        assert_eq!(status.entries, 4);
        assert_eq!(
            status
                .skipped
                .iter()
                .map(|(kind, count)| (kind.as_str(), *count))
                .collect::<Vec<_>>(),
            [("SCRIPT", 1)]
        );
        // The IP-ASN lines have no ASN data to look in, and say so.
        assert_eq!(routed.missing_data_sets(), ["asn-13335", "asn-15169"]);
        // The USER-AGENT line inside the set turns on per-request routing.
        assert!(routed.uses_request());
        assert_eq!(
            routed.route(&domain("x.ads.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        runtime.shutdown_background();
    }

    #[test]
    fn failed_downloads_keep_the_cached_entries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/gone", listener.local_addr().unwrap());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let routed = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}","domain_suffix":["cached.test"]}}"#),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        // The inline entries are not empty, so nothing is due until asked.
        routed.rule_sets().refresh_now();
        wait_until(|| routed.rule_sets().status()[0].last_error.is_some());
        let status = &routed.rule_sets().status()[0];
        assert_eq!(status.last_error, Some("http_status"));
        assert_eq!(status.entries, 1);
        assert_eq!(status.updated_at_ms, None);
        assert_eq!(
            routed.route(&domain("www.cached.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        runtime.shutdown_background();
    }

    /// Serves the list at `/ads.list` and `signature` at `/ads.list.sig`.
    fn signed_server(body: &'static [u8], signature: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ads.list", listener.local_addr().unwrap());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let read = stream.read(&mut request).unwrap_or(0);
                let line = String::from_utf8_lossy(&request[..read]);
                let reply: Vec<u8> = if line.starts_with("GET /ads.list.sig ") {
                    signature.as_bytes().to_vec()
                } else {
                    body.to_vec()
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&reply);
            }
        });
        url
    }

    fn signed_routed(url: &str, public_key: &str) -> Arc<RoutedOutbound> {
        routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}","public_key":"{public_key}","domain_suffix":["cached.test"]}}"#),
        )
        .unwrap()
    }

    fn run_once(routed: &Arc<RoutedOutbound>) -> tokio::runtime::Runtime {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        routed.rule_sets().refresh_now();
        runtime
    }

    #[test]
    fn signed_sets_install_only_with_a_valid_signature() {
        use base64::Engine as _;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        const LIST: &[u8] = b"DOMAIN-SUFFIX,ads.test\n";
        let rng = ring::rand::SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let public_key = encode(pair.public_key().as_ref());

        // A valid signature: the list replaces the cached copy.
        let url = signed_server(LIST, encode(pair.sign(LIST).as_ref()));
        let good = signed_routed(&url, &public_key);
        assert!(good.rule_sets().status()[0].signed);
        let runtime = run_once(&good);
        wait_until(|| good.rule_sets().status()[0].updated_at_ms.is_some());
        assert_eq!(
            good.route(&domain("x.ads.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        runtime.shutdown_background();

        // A signature over other bytes: the cached copy stays.
        let url = signed_server(
            LIST,
            encode(pair.sign(b"DOMAIN-SUFFIX,other.test\n").as_ref()),
        );
        let bad = signed_routed(&url, &public_key);
        let runtime = run_once(&bad);
        wait_until(|| bad.rule_sets().status()[0].last_error.is_some());
        assert_eq!(
            bad.rule_sets().status()[0].last_error,
            Some("signature_invalid")
        );
        assert_eq!(
            bad.route(&domain("x.ads.test", 443)),
            RouteOutcome::Node("hk".to_string())
        );
        assert_eq!(
            bad.route(&domain("www.cached.test", 443)),
            RouteOutcome::Reject(RejectKind::Reject)
        );
        runtime.shutdown_background();
    }

    #[test]
    fn signature_settings_are_checked() {
        for set in [
            r#""ads":{"url":"https://example.test/list","public_key":"c2hvcnQ="}"#,
            r#""ads":{"url":"https://example.test/list","signature_url":"https://example.test/list.sig"}"#,
            r#""ads":{"url":"https://example.test/list","public_key":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","signature_url":"ftp://x/sig"}"#,
        ] {
            assert!(
                routed(r#""RULE-SET,ads,REJECT","FINAL,hk""#, set).is_err(),
                "{set}"
            );
        }
        let unsigned = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            r#""ads":{"url":"https://example.test/list"}"#,
        )
        .unwrap();
        assert!(!unsigned.rule_sets().status()[0].signed);
    }

    #[test]
    fn downloads_are_kept_for_the_next_start() {
        let (url, hits) = list_server("DOMAIN-SUFFIX,ads.test\nUSER-AGENT,BadBot*\n");
        let dir = cache_dir("next-start");

        // Nothing kept yet: the set starts empty and is downloaded at once.
        let first = cached_ads(&url, &dir);
        let status = &first.rule_sets().status()[0];
        assert_eq!(status.entries, 0);
        assert!(!status.from_cache);
        let runtime = updating(&first);
        wait_until(|| first.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        let downloaded = first.rule_sets().status()[0].clone();
        assert_eq!(downloaded.entries, 2);
        assert!(!downloaded.from_cache);
        assert_eq!(downloaded.cache_error, None);
        assert_eq!(kept_copies(&dir), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // The next start routes with the kept copy before any download,
        // rules other than domains included...
        let second = cached_ads(&url, &dir);
        let status = second.rule_sets().status()[0].clone();
        assert!(status.from_cache);
        assert_eq!(status.entries, 2);
        assert_eq!(status.updated_at_ms, downloaded.updated_at_ms);
        assert_eq!(second.route(&domain("x.ads.test", 443)), rejected());
        assert!(second.uses_request());
        // ...and downloads again only once the interval is over, or when
        // asked.
        let runtime = updating(&second);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(second.rule_sets().refresh_now(), 1);
        wait_until(|| !second.rule_sets().status()[0].from_cache);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        runtime.shutdown_background();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kept_copy_outlives_failed_downloads() {
        let (url, _, up) = switchable_server("DOMAIN-SUFFIX,ads.test\n");
        let dir = cache_dir("failures");
        let first = cached_ads(&url, &dir);
        let runtime = updating(&first);
        wait_until(|| first.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        let kept_at = first.rule_sets().status()[0].updated_at_ms;

        // The list is gone: the next start still routes with the kept copy,
        // and a failed download changes nothing but the error.
        up.store(false, Ordering::SeqCst);
        let second = cached_ads(&url, &dir);
        let runtime = updating(&second);
        second.rule_sets().refresh_now();
        wait_until(|| second.rule_sets().status()[0].last_error.is_some());
        runtime.shutdown_background();
        let status = second.rule_sets().status()[0].clone();
        assert_eq!(status.last_error, Some("http_status"));
        assert!(status.from_cache);
        assert_eq!(status.entries, 1);
        assert_eq!(status.updated_at_ms, kept_at);
        assert_eq!(second.route(&domain("x.ads.test", 443)), rejected());
        // Nor did it touch the copy.
        assert!(cached_ads(&url, &dir).rule_sets().status()[0].from_cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kept_copies_follow_the_url_not_the_set_name() {
        let (first_url, _) = list_server("DOMAIN-SUFFIX,first.test\n");
        let (second_url, _) = list_server("DOMAIN-SUFFIX,second.test\n");
        let dir = cache_dir("by-url");
        let rules = r#""RULE-SET,local-1,REJECT","RULE-SET,local-2,DIRECT","FINAL,hk""#;
        let build = |one: &str, two: &str| {
            routed_with(
                rules,
                &format!(r#""local-1":{{"url":"{one}"}},"local-2":{{"url":"{two}"}}"#),
                &cache_dir_member(&dir),
            )
            .unwrap()
        };
        let before = build(&first_url, &second_url);
        let runtime = updating(&before);
        wait_until(|| {
            before
                .rule_sets()
                .status()
                .iter()
                .all(|set| set.updated_at_ms.is_some())
        });
        runtime.shutdown_background();
        assert_eq!(kept_copies(&dir), 2);

        // The user moved the lines, so each name now stands for the other
        // list: each starts with that list's copy.
        let after = build(&second_url, &first_url);
        assert!(after.rule_sets().status().iter().all(|set| set.from_cache));
        assert_eq!(after.route(&domain("www.second.test", 443)), rejected());
        assert_eq!(
            after.route(&domain("www.first.test", 443)),
            RouteOutcome::Direct
        );
        // A list never downloaded has no copy, whatever its name.
        let (third_url, _) = list_server("DOMAIN-SUFFIX,third.test\n");
        let other = build(&third_url, &first_url);
        let status = other.rule_sets().status();
        assert!(!status[0].from_cache);
        assert_eq!(status[0].entries, 0);
        assert!(status[1].from_cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_first_download_comes_an_interval_after_the_kept_one() {
        let dir = cache_dir("due");
        let build = || {
            routed_with(
                r#""RULE-SET,ads,REJECT","FINAL,hk""#,
                r#""ads":{"url":"http://127.0.0.1:9/ads.list","interval_secs":3600}"#,
                &cache_dir_member(&dir),
            )
            .unwrap()
        };
        // No copy: right away.
        let first = build();
        let remote = first.rule_sets().remotes()[0].clone();
        assert_eq!(
            first.rule_sets().first_update_delay(&remote),
            Duration::ZERO
        );
        let cache = first.rule_sets().cache().unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Kept ten minutes ago: the rest of the hour.
        cache
            .store(&remote, None, b"DOMAIN-SUFFIX,ads.test\n", now_ms - 600_000)
            .unwrap();
        let delay = build().rule_sets().first_update_delay(&remote);
        assert!(
            (Duration::from_secs(2900)..=Duration::from_secs(3000)).contains(&delay),
            "{delay:?}"
        );
        // Kept two hours ago: right away.
        cache
            .store(
                &remote,
                None,
                b"DOMAIN-SUFFIX,ads.test\n",
                now_ms - 7_200_000,
            )
            .unwrap();
        assert_eq!(
            build().rule_sets().first_update_delay(&remote),
            Duration::ZERO
        );
        // Without a cache directory inline entries wait a whole interval, as
        // before.
        let inline = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            r#""ads":{"url":"http://127.0.0.1:9/ads.list","interval_secs":3600,"domain_suffix":["cached.test"]}"#,
        )
        .unwrap();
        let sets = inline.rule_sets();
        assert_eq!(
            sets.first_update_delay(&sets.remotes()[0]),
            Duration::from_secs(3600)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_copies_are_ignored_and_written_again() {
        let (url, hits) = list_server("DOMAIN-SUFFIX,ads.test\n");
        let dir = cache_dir("damaged");
        let first = cached_ads(&url, &dir);
        let runtime = updating(&first);
        wait_until(|| first.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        let sets = first.rule_sets();
        let path = sets.cache().unwrap().path(&sets.remotes()[0]);
        let whole = std::fs::read(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();

        // The cut copy is not used: the set starts empty, no error, and is
        // downloaded again right away...
        let second = cached_ads(&url, &dir);
        let status = second.rule_sets().status()[0].clone();
        assert!(!status.from_cache);
        assert_eq!(status.entries, 0);
        assert_eq!(second.route(&domain("x.ads.test", 443)), proxied());
        let runtime = updating(&second);
        wait_until(|| second.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        // ...which keeps a whole copy again.
        assert!(cached_ads(&url, &dir).rule_sets().status()[0].from_cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn downloads_work_when_the_cache_cannot_be_written() {
        let (url, _) = list_server("DOMAIN-SUFFIX,ads.test\n");
        let dir = cache_dir("unwritable");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        let routed = cached_ads(&url, &file.join("cache"));
        let runtime = updating(&routed);
        wait_until(|| routed.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        let status = routed.rule_sets().status()[0].clone();
        assert_eq!(status.entries, 1);
        assert_eq!(status.cache_error, Some("cache_write_failed"));
        assert_eq!(routed.route(&domain("x.ads.test", 443)), rejected());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_sets_keep_only_verified_copies() {
        use base64::Engine as _;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        const LIST: &[u8] = b"DOMAIN-SUFFIX,ads.test\n";
        let rng = ring::rand::SystemRandom::new();
        let key_pair = || {
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap()
        };
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let pair = key_pair();
        let public_key = encode(pair.public_key().as_ref());
        let dir = cache_dir("signed");
        let signed = |url: &str, public_key: &str| {
            routed_with(
                r#""RULE-SET,ads,REJECT","FINAL,hk""#,
                &format!(r#""ads":{{"url":"{url}","public_key":"{public_key}"}}"#),
                &cache_dir_member(&dir),
            )
            .unwrap()
        };

        // A signature over other bytes: nothing is kept.
        let url = signed_server(
            LIST,
            encode(pair.sign(b"DOMAIN-SUFFIX,other.test\n").as_ref()),
        );
        let bad = signed(&url, &public_key);
        let runtime = updating(&bad);
        wait_until(|| bad.rule_sets().status()[0].last_error.is_some());
        runtime.shutdown_background();
        assert_eq!(
            bad.rule_sets().status()[0].last_error,
            Some("signature_invalid")
        );
        assert_eq!(kept_copies(&dir), 0);

        // A valid one is kept, and checked again at the next start.
        let url = signed_server(LIST, encode(pair.sign(LIST).as_ref()));
        let good = signed(&url, &public_key);
        let runtime = updating(&good);
        wait_until(|| good.rule_sets().status()[0].updated_at_ms.is_some());
        runtime.shutdown_background();
        assert_eq!(kept_copies(&dir), 1);
        let again = signed(&url, &public_key);
        assert!(again.rule_sets().status()[0].from_cache);
        assert_eq!(again.route(&domain("x.ads.test", 443)), rejected());

        // Under another key the copy does not count.
        let rotated = signed(&url, &encode(key_pair().public_key().as_ref()));
        assert!(!rotated.rule_sets().status()[0].from_cache);
        assert_eq!(rotated.route(&domain("x.ads.test", 443)), proxied());

        // A copy whose list changed on disk no longer verifies.
        let sets = again.rule_sets();
        let signature = encode(pair.sign(LIST).as_ref());
        sets.cache()
            .unwrap()
            .store(
                &sets.remotes()[0],
                Some(signature.as_bytes()),
                b"DOMAIN-SUFFIX,evil.test\n",
                1,
            )
            .unwrap();
        let tampered = signed(&url, &public_key);
        assert!(!tampered.rule_sets().status()[0].from_cache);
        assert_eq!(tampered.route(&domain("x.evil.test", 443)), proxied());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serves `body` at `/ads.list` and `signature` at `/ads.list.sig`, and
    /// redirects to them: `/abs` with an absolute `Location`, `/dir/rel` with
    /// a relative one (to `/dir/moved`, which sends an absolute path on),
    /// `/old.list` and `/old.list.sig` with `307` / `308`, `/loop` to itself
    /// and `/nowhere` without a `Location`.
    fn redirecting_server(body: &'static [u8], signature: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let own = base.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let read = stream.read(&mut request).unwrap_or(0);
                let line = String::from_utf8_lossy(&request[..read]);
                let path = line.split(' ').nth(1).unwrap_or_default().to_string();
                let redirect = |status: &str, location: Option<&str>| {
                    let location =
                        location.map_or(String::new(), |to| format!("Location: {to}\r\n"));
                    format!(
                        "HTTP/1.1 {status}\r\n{location}Content-Length: 5\r\nConnection: close\r\n\r\nmoved"
                    )
                    .into_bytes()
                };
                let reply: Vec<u8> = match path.as_str() {
                    "/ads.list" | "/ads.list.sig" => {
                        let content = if path == "/ads.list" {
                            body.to_vec()
                        } else {
                            signature.as_bytes().to_vec()
                        };
                        let mut reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            content.len()
                        )
                        .into_bytes();
                        reply.extend_from_slice(&content);
                        reply
                    }
                    "/abs" => redirect("302 Found", Some(format!("{own}/ads.list").as_str())),
                    "/dir/rel" => redirect("302 Found", Some("moved")),
                    "/dir/moved" => redirect("301 Moved Permanently", Some("/ads.list")),
                    "/old.list" => redirect("307 Temporary Redirect", Some("/ads.list")),
                    "/old.list.sig" => redirect("308 Permanent Redirect", Some("/ads.list.sig")),
                    "/loop" => redirect("302 Found", Some("/loop")),
                    "/nowhere" => redirect("302 Found", None),
                    _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                };
                let _ = stream.write_all(&reply);
            }
        });
        base
    }

    #[test]
    fn redirected_downloads_install() {
        let base = redirecting_server(b"DOMAIN-SUFFIX,ads.test\n", String::new());
        for path in ["/abs", "/dir/rel", "/old.list"] {
            let routed = routed(
                r#""RULE-SET,ads,REJECT","FINAL,hk""#,
                &format!(r#""ads":{{"url":"{base}{path}"}}"#),
            )
            .unwrap();
            let runtime = updating(&routed);
            wait_until(|| {
                let status = &routed.rule_sets().status()[0];
                status.updated_at_ms.is_some() || status.last_error.is_some()
            });
            let status = &routed.rule_sets().status()[0];
            assert_eq!(status.last_error, None, "{path}");
            assert_eq!(status.entries, 1, "{path}");
            assert_eq!(
                routed.route(&domain("x.ads.test", 443)),
                rejected(),
                "{path}"
            );
            runtime.shutdown_background();
        }
    }

    #[test]
    fn redirect_loops_and_redirects_without_a_location_fail() {
        let base = redirecting_server(b"DOMAIN-SUFFIX,ads.test\n", String::new());
        for (path, error) in [("/loop", "too_many_redirects"), ("/nowhere", "http_status")] {
            let routed = routed(
                r#""RULE-SET,ads,REJECT","FINAL,hk""#,
                &format!(r#""ads":{{"url":"{base}{path}"}}"#),
            )
            .unwrap();
            let runtime = updating(&routed);
            wait_until(|| routed.rule_sets().status()[0].last_error.is_some());
            assert_eq!(
                routed.rule_sets().status()[0].last_error,
                Some(error),
                "{path}"
            );
            assert_eq!(routed.route(&domain("x.ads.test", 443)), proxied());
            runtime.shutdown_background();
        }
    }

    #[test]
    fn signed_sets_verify_after_redirects() {
        use base64::Engine as _;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        const LIST: &[u8] = b"DOMAIN-SUFFIX,ads.test\n";
        let rng = ring::rand::SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        // `<url>.sig` comes from the configured URL (`/old.list.sig`), which
        // redirects to the signature of the list it redirects to.
        let base = redirecting_server(LIST, encode(pair.sign(LIST).as_ref()));
        let routed = signed_routed(
            &format!("{base}/old.list"),
            &encode(pair.public_key().as_ref()),
        );
        let runtime = run_once(&routed);
        wait_until(|| {
            let status = &routed.rule_sets().status()[0];
            status.updated_at_ms.is_some() || status.last_error.is_some()
        });
        assert_eq!(routed.rule_sets().status()[0].last_error, None);
        assert_eq!(routed.route(&domain("x.ads.test", 443)), rejected());
        runtime.shutdown_background();
    }
}
