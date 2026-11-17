//! Rule-based outbound dispatch with recording test outbounds.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use config_core::routing::{PolicyGroupSpec, RejectKind, RouteOutcome, RoutingSpec};
use config_core::rule_set::RuleSet;
use engine_embedded::reject::STORM_LIMIT;
use engine_embedded::routing::{DomainResolver, RoutedOutbound};
use engine_outbound::reject::{self, RejectAction};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};

/// Records the target and fails, so tests see which outbound was chosen.
struct Recording {
    name: &'static str,
    hits: Arc<Mutex<Vec<&'static str>>>,
}

impl TcpOutbound for Recording {
    fn protocol(&self) -> &'static str {
        "test-recording"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.hits.lock().unwrap().push(self.name);
            Err(io::Error::other("recording outbound does not connect"))
        })
    }
}

fn routed(hits: &Arc<Mutex<Vec<&'static str>>>) -> RoutedOutbound {
    let recording = |name| -> Arc<dyn TcpOutbound> {
        Arc::new(Recording {
            name,
            hits: hits.clone(),
        })
    };
    let nodes = BTreeMap::from([
        ("hk-1".to_string(), recording("hk-1")),
        ("jp-1".to_string(), recording("jp-1")),
    ]);
    let spec = RoutingSpec {
        rules: vec![
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,198.51.100.0/24,REJECT,no-resolve".to_string(),
            "DOMAIN-SUFFIX,example.jp,jp-1".to_string(),
            "IP-CIDR6,2001:db8::/32,Auto".to_string(),
            "FINAL,Proxy".to_string(),
        ],
        groups: vec![
            PolicyGroupSpec {
                id: "Proxy".to_string(),
                kind: "select".to_string(),
                members: vec!["Auto".to_string(), "jp-1".to_string()],
                default: Some("jp-1".to_string()),
                url: None,
                interval_secs: None,
                tolerance_ms: None,
                ..PolicyGroupSpec::default()
            },
            PolicyGroupSpec {
                id: "Auto".to_string(),
                kind: "url-test".to_string(),
                members: vec!["hk-1".to_string(), "jp-1".to_string()],
                default: None,
                url: None,
                interval_secs: None,
                tolerance_ms: None,
                ..PolicyGroupSpec::default()
            },
        ],
    };
    RoutedOutbound::new(&spec, recording("direct"), nodes).expect("spec should validate")
}

fn ip(addr: &str) -> TargetAddr {
    TargetAddr::Ip(addr.parse::<SocketAddr>().unwrap())
}

#[test]
fn routes_targets_by_rules_and_groups() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits);

    assert_eq!(outbound.route(&ip("10.1.2.3:443")), RouteOutcome::Direct);
    assert_eq!(
        outbound.route(&ip("198.51.100.7:443")),
        RouteOutcome::Reject(RejectKind::Reject)
    );
    assert_eq!(
        outbound.route(&ip("[2001:db8::1]:443")),
        RouteOutcome::Node("hk-1".to_string())
    );
    assert_eq!(
        outbound.route(&ip("203.0.113.9:443")),
        RouteOutcome::Node("jp-1".to_string())
    );
    assert_eq!(
        outbound.route(&TargetAddr::Domain("www.example.jp".to_string(), 443)),
        RouteOutcome::Node("jp-1".to_string())
    );
    // A domain that reaches an IP rule is not resolved, so it is rejected.
    assert_eq!(
        outbound.route(&TargetAddr::Domain("other.example".to_string(), 443)),
        RouteOutcome::Reject(RejectKind::Reject)
    );
}

/// Answers from a fixed table and records every lookup.
struct FixedResolver {
    lookups: Arc<Mutex<Vec<String>>>,
}

impl DomainResolver for FixedResolver {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        Box::pin(async move {
            self.lookups.lock().unwrap().push(domain.to_string());
            match domain {
                "v6.example" => Ok("2001:db8::5".parse().unwrap()),
                "v4.example" => Ok("203.0.113.9".parse().unwrap()),
                _ => Err(io::Error::new(io::ErrorKind::NotFound, "no such domain")),
            }
        })
    }
}

#[test]
fn domains_are_resolved_only_when_an_ip_rule_needs_them() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let lookups = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits).with_resolver(Arc::new(FixedResolver {
        lookups: lookups.clone(),
    }));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let domain = |name: &str| TargetAddr::Domain(name.to_string(), 443);

    runtime.block_on(async {
        // A domain rule matches before any IP rule asks for an address.
        assert_eq!(
            outbound.route_resolving(&domain("www.example.jp")).await,
            RouteOutcome::Node("jp-1".to_string())
        );
        // The resolved address matches the IP-CIDR6 rule (Auto -> hk-1).
        assert_eq!(
            outbound.route_resolving(&domain("v6.example")).await,
            RouteOutcome::Node("hk-1".to_string())
        );
        // An address no IP rule holds falls through to FINAL.
        assert_eq!(
            outbound.route_resolving(&domain("v4.example")).await,
            RouteOutcome::Node("jp-1".to_string())
        );
        // A failed lookup rejects the connection, as in sing-box.
        assert_eq!(
            outbound.route_resolving(&domain("missing.example")).await,
            RouteOutcome::Reject(RejectKind::Reject)
        );
        // IP targets never trigger a lookup.
        assert_eq!(
            outbound.route_resolving(&ip("10.1.2.3:443")).await,
            RouteOutcome::Direct
        );
        let _ = outbound.connect(&domain("v6.example")).await;
    });

    assert_eq!(
        *lookups.lock().unwrap(),
        vec!["v6.example", "v4.example", "missing.example", "v6.example"]
    );
    assert_eq!(*hits.lock().unwrap(), vec!["hk-1"]);
}

#[test]
fn connect_dispatches_to_the_routed_outbound() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    runtime.block_on(async {
        for target in [
            "10.1.2.3:443",
            "[2001:db8::1]:443",
            "203.0.113.9:443",
            "198.51.100.7:443",
        ] {
            let _ = outbound.connect(&ip(target)).await;
        }
    });

    assert_eq!(*hits.lock().unwrap(), vec!["direct", "hk-1", "jp-1"]);
    let rejected = runtime
        .block_on(outbound.connect(&ip("198.51.100.7:443")))
        .err()
        .expect("rejected target should fail");
    assert_eq!(rejected.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn rule_sets_route_large_lists_without_resolving_domains() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let recording = |name| -> Arc<dyn TcpOutbound> {
        Arc::new(Recording {
            name,
            hits: hits.clone(),
        })
    };
    let nodes = BTreeMap::from([("proxy".to_string(), recording("proxy"))]);
    let spec = RoutingSpec {
        rules: vec![
            "RULE-SET,china,DIRECT".to_string(),
            "FINAL,proxy".to_string(),
        ],
        groups: Vec::new(),
    };
    let domains: Vec<String> = (0..50_000).map(|i| format!("site{i}.cn")).collect();
    let china = RuleSet::new(domains.iter().map(String::as_str), ["192.0.2.0/24"]).unwrap();
    let outbound = RoutedOutbound::with_rule_sets(
        &spec,
        recording("direct"),
        nodes.clone(),
        BTreeMap::from([("china".to_string(), china)]),
    )
    .expect("rule set is configured");

    let domain = |name: &str| TargetAddr::Domain(name.to_string(), 443);
    assert_eq!(
        outbound.route(&domain("www.site49999.cn")),
        RouteOutcome::Direct
    );
    assert_eq!(outbound.route(&ip("192.0.2.9:443")), RouteOutcome::Direct);
    assert_eq!(
        outbound.route(&domain("example.com")),
        RouteOutcome::Node("proxy".to_string())
    );
    assert_eq!(
        outbound.route(&ip("203.0.113.9:443")),
        RouteOutcome::Node("proxy".to_string())
    );

    // A RULE-SET rule naming a set the config does not carry is rejected.
    assert!(RoutedOutbound::new(&spec, recording("direct"), nodes).is_err());
}

#[test]
fn url_test_groups_follow_recorded_latencies() {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let outbound = routed(&hits);
    let v6 = ip("[2001:db8::1]:443");

    // Until a check finishes, the url-test group uses its first member.
    assert_eq!(outbound.route(&v6), RouteOutcome::Node("hk-1".to_string()));

    outbound.record_latency("Auto", "hk-1", Some(240));
    outbound.record_latency("Auto", "jp-1", Some(80));
    assert_eq!(outbound.route(&v6), RouteOutcome::Node("jp-1".to_string()));

    // A failed check removes the member from the choice.
    outbound.record_latency("Auto", "jp-1", None);
    assert_eq!(outbound.route(&v6), RouteOutcome::Node("hk-1".to_string()));
}

fn rejecting() -> RoutedOutbound {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let direct: Arc<dyn TcpOutbound> = Arc::new(Recording {
        name: "direct",
        hits,
    });
    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN,plain.example,REJECT".to_string(),
            "DOMAIN,nodrop.example,REJECT-NO-DROP".to_string(),
            "DOMAIN,drop.example,REJECT-DROP".to_string(),
            "DOMAIN,gif.example,REJECT-TINYGIF".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: Vec::new(),
    };
    RoutedOutbound::new(&spec, direct, BTreeMap::new()).expect("spec should validate")
}

fn named(domain: &str) -> TargetAddr {
    TargetAddr::Domain(domain.to_string(), 443)
}

#[tokio::test]
async fn reject_variants_reach_the_inbound_as_their_action() {
    let outbound = rejecting();
    for (domain, action, shown) in [
        ("plain.example", RejectAction::Close, "REJECT"),
        ("nodrop.example", RejectAction::Close, "REJECT-NO-DROP"),
        ("drop.example", RejectAction::Drop, "REJECT-DROP"),
        ("gif.example", RejectAction::TinyGif, "REJECT-TINYGIF"),
    ] {
        let error = match outbound.connect(&named(domain)).await {
            Ok(_) => panic!("{domain} must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{domain}");
        assert_eq!(reject::rejection(&error), Some(action), "{domain}");

        let (route, picked) = outbound.route_flow(&named(domain), None, None).await;
        assert!(picked.is_none(), "{domain}");
        assert_eq!(route.outbound, shown);
        assert_eq!(route.chain, vec![shown.to_string()]);
    }
}

#[tokio::test]
async fn a_rejected_host_that_keeps_retrying_is_dropped() {
    let outbound = rejecting();
    // Ten rejections in a row are answered as REJECT ...
    for attempt in 0..STORM_LIMIT {
        let (route, _) = outbound
            .route_flow(&named("plain.example"), None, None)
            .await;
        assert_eq!(route.outbound, "REJECT", "attempt {attempt}");
        assert_eq!(route.reject, Some(RejectKind::Reject));
    }
    // ... and the next ones within the window like REJECT-DROP.
    let (route, _) = outbound
        .route_flow(&named("plain.example"), None, None)
        .await;
    assert_eq!(route.outbound, "REJECT-DROP");
    assert_eq!(route.reject, Some(RejectKind::Drop));
    let error = match outbound.connect(&named("plain.example")).await {
        Ok(_) => panic!("must stay rejected"),
        Err(error) => error,
    };
    assert_eq!(reject::rejection(&error), Some(RejectAction::Drop));

    // Hosts are counted apart, and REJECT-NO-DROP never upgrades.
    let (route, _) = outbound
        .route_flow(&ip("192.0.2.9:443"), Some("other.example"), None)
        .await;
    assert_eq!(route.outbound, "DIRECT");
    for _ in 0..3 * STORM_LIMIT {
        let (route, _) = outbound
            .route_flow(&named("nodrop.example"), None, None)
            .await;
        assert_eq!(route.outbound, "REJECT-NO-DROP");
    }
    // Synchronous lookups (DNS servers, status) do not count.
    for _ in 0..3 * STORM_LIMIT {
        assert_eq!(
            outbound.route(&named("gif.example")),
            RouteOutcome::Reject(RejectKind::TinyGif)
        );
    }
}

fn scripted(rules: &[&str], scripts: engine_embedded::rule_scripts::RuleScripts) -> RoutedOutbound {
    let direct: Arc<dyn TcpOutbound> = Arc::new(Recording {
        name: "direct",
        hits: Arc::default(),
    });
    let spec = RoutingSpec {
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
        groups: Vec::new(),
    };
    RoutedOutbound::new(&spec, direct, BTreeMap::new())
        .expect("spec should validate")
        .with_rule_scripts(scripts)
        .expect("every SCRIPT rule names a script")
}

#[test]
fn script_rules_must_name_a_configured_script() {
    use engine_embedded::routing::reject_code;
    use engine_embedded::rule_scripts::{RuleScript, RuleScripts};

    let spec = RoutingSpec {
        rules: vec![
            "SCRIPT,missing,DIRECT".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: Vec::new(),
    };
    let direct: Arc<dyn TcpOutbound> = Arc::new(Recording {
        name: "direct",
        hits: Arc::default(),
    });
    let error = RoutedOutbound::new(&spec, direct, BTreeMap::new())
        .unwrap()
        .with_rule_scripts(RuleScripts::default())
        .err()
        .expect("an unknown script is rejected");
    assert_eq!(
        error.message,
        "a SCRIPT rule names a script that is not configured"
    );

    let known = RuleScripts::new(BTreeMap::from([(
        "known".to_string(),
        RuleScript {
            source: "$done({matched: true})".into(),
            argument: String::new(),
            timeout: std::time::Duration::from_secs(1),
        },
    )]));
    let outbound = scripted(&["SCRIPT,known,DIRECT", "FINAL,DIRECT"], known);
    let rejection = outbound
        .reload_rules(
            &[
                "SCRIPT,other,DIRECT".to_string(),
                "FINAL,DIRECT".to_string(),
            ],
            true,
        )
        .expect_err("a reload naming an unknown script is rejected");
    assert_eq!(rejection.line, Some(0));
    assert_eq!(rejection.code, reject_code::UNKNOWN_SCRIPT);
    assert!(outbound
        .reload_rules(
            &[
                "SCRIPT,known,REJECT".to_string(),
                "FINAL,DIRECT".to_string()
            ],
            true,
        )
        .is_ok());
}

#[cfg(feature = "scripts")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_rules_route_by_what_the_script_decides() {
    use engine_embedded::rule_scripts::{RuleScript, RuleScripts};
    use std::time::Duration;

    let script = |source: &str, timeout: Duration| RuleScript {
        source: source.into(),
        argument: "443".to_string(),
        timeout,
    };
    let scripts = RuleScripts::new(BTreeMap::from([
        (
            "corp".to_string(),
            script(
                "$done({matched: $request.hostname.endsWith('.corp.example') \
                 && $request.destPort === Number($argument) && $request.protocol === 'TCP'})",
                Duration::from_secs(1),
            ),
        ),
        (
            "throws".to_string(),
            script("throw new Error('boom')", Duration::from_secs(1)),
        ),
        (
            "slow".to_string(),
            script(
                "setTimeout(function () { $done({matched: true}); }, 5000);",
                Duration::from_millis(200),
            ),
        ),
        (
            "by-address".to_string(),
            script(
                "$done({matched: $request.destIP === '198.51.100.7' && $request.hostname === null})",
                Duration::from_secs(1),
            ),
        ),
    ]));
    let outbound = scripted(
        &[
            "DOMAIN,early.example,REJECT-NO-DROP",
            "SCRIPT,corp,REJECT-TINYGIF",
            "SCRIPT,throws,REJECT-DROP",
            "SCRIPT,slow,REJECT",
            "SCRIPT,by-address,REJECT-DROP",
            "FINAL,DIRECT",
        ],
        scripts,
    );
    let domain = |name: &str, port| TargetAddr::Domain(name.to_string(), port);

    // A rule before the scripts decides without running them.
    assert_eq!(
        outbound
            .route_resolving(&domain("early.example", 443))
            .await,
        RouteOutcome::Reject(RejectKind::NoDrop)
    );
    // The script sees the connection and decides.
    let (route, _) = outbound
        .route_flow(&domain("git.corp.example", 443), None, None)
        .await;
    assert_eq!(route.rule, "SCRIPT,corp");
    assert_eq!(route.outbound, "REJECT-TINYGIF");
    // No match, a throwing script and one that runs out of time all fall
    // through to the next rule.
    let started = std::time::Instant::now();
    let (route, _) = outbound
        .route_flow(&domain("git.corp.example", 80), None, None)
        .await;
    assert_eq!(route.rule, "FINAL");
    assert_eq!(route.outbound, "DIRECT");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        outbound.route_resolving(&ip("198.51.100.7:443")).await,
        RouteOutcome::Reject(RejectKind::Drop)
    );
    // Decisions without a connection never run scripts.
    assert_eq!(
        outbound.route(&domain("git.corp.example", 443)),
        RouteOutcome::Direct
    );
}
