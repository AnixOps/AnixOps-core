//! Self-healing policy groups: a failed connection retests its member, a
//! network change forgets every result, `evaluate_before_use` holds a
//! connection until its group is checked, url-test keeps its member within
//! the tolerance, and subnet groups follow the reported network.

#![cfg(feature = "local-proxy")]

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use config_core::routing::{
    NetworkContext, NetworkKind, NetworkRuleSpec, PolicyGroupSpec, RouteOutcome, RoutingSpec,
};
use engine_embedded::connections::Dispatcher;
use engine_embedded::control;
use engine_embedded::routing::{RouteInfo, RoutedOutbound};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROBE_URL: &str = "http://probe.test/generate_204";

/// A node that answers the health check with `204` while `alive`, and
/// refuses every connection otherwise. Counts the connections it was asked
/// for.
#[derive(Default)]
struct Node {
    dead: AtomicBool,
    dials: AtomicUsize,
}

impl Node {
    fn alive() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn dead() -> Arc<Self> {
        let node = Self::default();
        node.dead.store(true, Ordering::SeqCst);
        Arc::new(node)
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }
}

impl TcpOutbound for Node {
    fn protocol(&self) -> &'static str {
        "test-node"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            if self.dead.load(Ordering::SeqCst) {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = server.read(&mut request).await;
                let _ = server
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}

fn url_test(id: &str, evaluate_before_use: bool) -> PolicyGroupSpec {
    PolicyGroupSpec {
        id: id.to_string(),
        kind: "url-test".to_string(),
        members: vec!["hk-1".to_string(), "jp-1".to_string()],
        url: Some(PROBE_URL.to_string()),
        evaluate_before_use,
        ..PolicyGroupSpec::default()
    }
}

fn routed(hk: &Arc<Node>, jp: &Arc<Node>, group: PolicyGroupSpec) -> Arc<RoutedOutbound> {
    let nodes = BTreeMap::from([
        ("hk-1".to_string(), hk.clone() as Arc<dyn TcpOutbound>),
        ("jp-1".to_string(), jp.clone() as Arc<dyn TcpOutbound>),
    ]);
    let spec = RoutingSpec {
        rules: vec![format!("FINAL,{}", group.id)],
        groups: vec![group],
    };
    Arc::new(RoutedOutbound::new(&spec, Node::alive(), nodes).expect("spec should validate"))
}

fn target() -> TargetAddr {
    TargetAddr::Domain("www.example.test".to_string(), 443)
}

/// Polls `done` every 10 ms for up to 3 s.
async fn eventually(mut done: impl FnMut() -> bool) {
    for _ in 0..300 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition did not hold within 3 s");
}

#[tokio::test]
async fn a_failed_connection_probes_only_its_member_and_moves_the_group_on() {
    let (hk, jp) = (Node::alive(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", false));
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| routed.group_checked("Auto")).await;
    // Both answered; either may be a millisecond faster.
    let (route, _) = routed.route_flow(&target(), None, None).await;
    assert_eq!(route.chain[0], "Auto");
    let (used, other, other_name) = if route.outbound == "hk-1" {
        (&hk, &jp, "jp-1")
    } else {
        (&jp, &hk, "hk-1")
    };

    used.dead.store(true, Ordering::SeqCst);
    let other_dials = other.dials();
    assert!(routed.report_failure(&route));
    eventually(|| routed.route(&target()) == RouteOutcome::Node(other_name.to_string())).await;
    // Only the member that failed was probed, not the whole group.
    assert_eq!(other.dials(), other_dials);

    // Within the cooldown the same member is not probed again.
    assert!(!routed.report_failure(&route));
    checks.abort();
}

#[tokio::test]
async fn a_member_that_passes_its_retest_keeps_its_place() {
    let (hk, jp) = (Node::alive(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", false));
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| routed.group_checked("Auto")).await;
    let (route, _) = routed.route_flow(&target(), None, None).await;
    let used = if route.outbound == "hk-1" { &hk } else { &jp };
    let dials = used.dials();

    // The site refused, not the node: the retest passes and nothing moves.
    assert!(routed.report_failure(&route));
    eventually(|| used.dials() > dials).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node(route.outbound.clone())
    );
    checks.abort();
}

#[test]
fn failures_outside_health_checked_groups_ask_for_nothing() {
    let (hk, jp) = (Node::alive(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", false));
    let direct = RouteInfo {
        rule: "FINAL".to_string(),
        chain: vec!["DIRECT".to_string()],
        outbound: "DIRECT".to_string(),
        ..RouteInfo::default()
    };
    assert!(!routed.report_failure(&direct));
    let rejected = RouteInfo {
        rule: "FINAL".to_string(),
        chain: vec!["Auto".to_string(), "REJECT".to_string()],
        outbound: "REJECT".to_string(),
        reject: Some(config_core::routing::RejectKind::Reject),
    };
    assert!(!routed.report_failure(&rejected));
}

#[tokio::test]
async fn a_network_change_forgets_results_and_checks_on_next_use() {
    let (hk, jp) = (Node::dead(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", false));
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| routed.group_checked("Auto")).await;
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("jp-1".to_string())
    );

    assert_eq!(routed.forget_health(), 1);
    assert!(!routed.group_checked("Auto"));
    assert!(routed.groups()[0]
        .members
        .iter()
        .all(|member| member.latency_ms.is_none()));
    // Without evaluate_before_use the connection does not wait: it takes
    // the first member and asks for a check, which runs at once.
    let (route, _) = routed.route_flow(&target(), None, None).await;
    assert_eq!(route.outbound, "hk-1");
    eventually(|| routed.group_checked("Auto")).await;
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("jp-1".to_string())
    );
    checks.abort();
}

#[tokio::test]
async fn evaluate_before_use_holds_a_connection_until_its_group_is_checked() {
    let (hk, jp) = (Node::dead(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", true));
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| routed.group_checked("Auto")).await;

    routed.forget_health();
    // The first member is dead; the connection waits for the check and
    // goes to the member that answered instead.
    let (route, outbound) = routed.route_flow(&target(), None, None).await;
    assert_eq!(route.outbound, "jp-1");
    assert!(outbound.is_some());
    assert!(routed.group_checked("Auto"));
    checks.abort();
}

#[tokio::test]
async fn evaluate_before_use_never_waits_without_a_check_loop() {
    let (hk, jp) = (Node::dead(), Node::alive());
    let routed = routed(&hk, &jp, url_test("Auto", true));
    let started = tokio::time::Instant::now();
    let (route, _) = routed.route_flow(&target(), None, None).await;
    assert_eq!(route.outbound, "hk-1");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn url_test_keeps_its_member_within_the_tolerance() {
    let (hk, jp) = (Node::alive(), Node::alive());
    let mut group = url_test("Auto", false);
    group.tolerance_ms = Some(50);
    let routed = routed(&hk, &jp, group);

    routed.record_latency("Auto", "hk-1", Some(100));
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("hk-1".to_string())
    );
    // 30 ms faster is within the tolerance: no switch.
    routed.record_latency("Auto", "jp-1", Some(70));
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("hk-1".to_string())
    );
    assert_eq!(routed.groups()[0].now, "hk-1");
    // 60 ms faster is not.
    routed.record_latency("Auto", "jp-1", Some(40));
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("jp-1".to_string())
    );
    // Now jp-1 is current, hk-1 must beat it by more than 50 ms to win back.
    routed.record_latency("Auto", "hk-1", Some(10));
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("jp-1".to_string())
    );
    // A current member that fails its check is dropped at once.
    routed.record_latency("Auto", "jp-1", None);
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("hk-1".to_string())
    );
}

fn subnet_routed() -> Arc<RoutedOutbound> {
    let (hk, jp) = (Node::alive(), Node::alive());
    let group = PolicyGroupSpec {
        id: "ByNetwork".to_string(),
        kind: "subnet".to_string(),
        default: Some("hk-1".to_string()),
        network_rules: vec![
            NetworkRuleSpec {
                when: "SSID:Home".to_string(),
                target: "DIRECT".to_string(),
            },
            NetworkRuleSpec {
                when: "ROUTER:192.168.50.1".to_string(),
                target: "DIRECT".to_string(),
            },
            NetworkRuleSpec {
                when: "SUBNET:10.8.0.0/16".to_string(),
                target: "DIRECT".to_string(),
            },
            NetworkRuleSpec {
                when: "TYPE:CELLULAR".to_string(),
                target: "jp-1".to_string(),
            },
        ],
        ..PolicyGroupSpec::default()
    };
    routed(&hk, &jp, group)
}

#[test]
fn subnet_groups_follow_the_reported_network() {
    let routed = subnet_routed();
    let hk = RouteOutcome::Node("hk-1".to_string());
    // Unknown network: the default.
    assert_eq!(routed.route(&target()), hk);

    let home = NetworkContext {
        kind: Some(NetworkKind::Wifi),
        ssid: Some("Home".to_string()),
        ..NetworkContext::default()
    };
    assert!(routed.set_network(Some(home.clone())));
    assert_eq!(routed.route(&target()), RouteOutcome::Direct);
    // The same network again changes nothing.
    assert!(!routed.set_network(Some(home)));

    // SSIDs match exactly, case included.
    let other = NetworkContext {
        kind: Some(NetworkKind::Wifi),
        ssid: Some("home".to_string()),
        ..NetworkContext::default()
    };
    routed.set_network(Some(other));
    assert_eq!(routed.route(&target()), hk);

    let office = NetworkContext {
        kind: Some(NetworkKind::Wired),
        router: Some("192.168.50.1".parse::<IpAddr>().unwrap()),
        ..NetworkContext::default()
    };
    routed.set_network(Some(office));
    assert_eq!(routed.route(&target()), RouteOutcome::Direct);

    let vpn_lan = NetworkContext {
        addresses: vec!["10.8.3.4".parse().unwrap(), "fd00::4".parse().unwrap()],
        ..NetworkContext::default()
    };
    routed.set_network(Some(vpn_lan));
    assert_eq!(routed.route(&target()), RouteOutcome::Direct);

    let cellular = NetworkContext {
        kind: Some(NetworkKind::Cellular),
        ..NetworkContext::default()
    };
    routed.set_network(Some(cellular));
    assert_eq!(
        routed.route(&target()),
        RouteOutcome::Node("jp-1".to_string())
    );

    routed.set_network(None);
    assert_eq!(routed.route(&target()), hk);
    // The policy page shows the pick and every target as a member.
    let view = &routed.groups()[0];
    assert_eq!(view.kind, "subnet");
    assert_eq!(view.now, "hk-1");
    let members: Vec<_> = view.members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(members, vec!["hk-1", "DIRECT", "jp-1"]);
}

fn control_json(dispatcher: &Dispatcher, request: &str) -> serde_json::Value {
    serde_json::from_slice(&control::handle(dispatcher, request.as_bytes()).unwrap()).unwrap()
}

#[test]
fn set_network_and_reset_network_drive_the_groups() {
    let dispatcher = Dispatcher::routed(subnet_routed());
    let answer = control_json(
        &dispatcher,
        r#"{"cmd":"set_network","type":"wifi","ssid":"Home","bssid":"AA-BB-CC-DD-EE-FF","router":"192.168.1.1","addresses":["192.168.1.20"]}"#,
    );
    assert_eq!(answer["changed"], true);
    let groups = control_json(&dispatcher, r#"{"cmd":"groups"}"#);
    assert_eq!(groups["groups"][0]["now"], "DIRECT");
    // The Wi-Fi name never shows in the answers.
    assert!(!groups.to_string().contains("Home"));

    // Everything absent: unknown network, back to the default.
    let answer = control_json(&dispatcher, r#"{"cmd":"set_network"}"#);
    assert_eq!(answer["changed"], true);
    let groups = control_json(&dispatcher, r#"{"cmd":"groups"}"#);
    assert_eq!(groups["groups"][0]["now"], "hk-1");

    for bad in [
        r#"{"cmd":"set_network","type":"satellite"}"#,
        r#"{"cmd":"set_network","ssid":""}"#,
        r#"{"cmd":"set_network","ssid":"0123456789abcdef0123456789abcdefX"}"#,
        r#"{"cmd":"set_network","bssid":"not-a-mac"}"#,
        r#"{"cmd":"set_network","router":"gateway"}"#,
        r#"{"cmd":"set_network","addresses":["10.0.0.300"]}"#,
    ] {
        assert!(
            control::handle(&dispatcher, bad.as_bytes()).is_err(),
            "{bad}"
        );
    }

    let answer = control_json(&dispatcher, r#"{"cmd":"reset_network"}"#);
    assert_eq!(answer["health_forgotten"], 0);
}

/// A node that answers health checks after `delay`, counting the dials and
/// the most it was asked for at once (over every node sharing `gauge`).
struct Slow {
    delay: Duration,
    dials: AtomicUsize,
    gauge: Arc<Gauge>,
}

#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    peak: AtomicUsize,
}

impl TcpOutbound for Slow {
    fn protocol(&self) -> &'static str {
        "test-node"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let now = self.gauge.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.gauge.peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.gauge.now.fetch_sub(1, Ordering::SeqCst);
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = server.read(&mut request).await;
                let _ = server
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
            Ok(Box::new(client) as BoxStream)
        })
    }
}

fn slow_nodes(count: usize, gauge: &Arc<Gauge>) -> BTreeMap<String, Arc<Slow>> {
    (0..count)
        .map(|index| {
            (
                format!("n{index}"),
                Arc::new(Slow {
                    delay: Duration::from_millis(30),
                    dials: AtomicUsize::new(0),
                    gauge: gauge.clone(),
                }),
            )
        })
        .collect()
}

fn group_of(id: &str, members: &[&str], url: &str) -> PolicyGroupSpec {
    PolicyGroupSpec {
        id: id.to_string(),
        kind: "url-test".to_string(),
        members: members.iter().map(|member| member.to_string()).collect(),
        url: Some(url.to_string()),
        ..PolicyGroupSpec::default()
    }
}

fn routed_over(
    nodes: &BTreeMap<String, Arc<Slow>>,
    groups: Vec<PolicyGroupSpec>,
) -> Arc<RoutedOutbound> {
    let outbounds = nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.clone() as Arc<dyn TcpOutbound>))
        .collect();
    let spec = RoutingSpec {
        rules: vec![format!("FINAL,{}", groups[0].id)],
        groups,
    };
    Arc::new(RoutedOutbound::new(&spec, Node::alive(), outbounds).expect("spec should validate"))
}

#[tokio::test]
async fn a_node_in_several_groups_is_probed_once_per_url() {
    let gauge = Arc::new(Gauge::default());
    let nodes = slow_nodes(2, &gauge);
    let routed = routed_over(
        &nodes,
        vec![
            group_of("Auto", &["n0", "n1"], PROBE_URL),
            group_of("HK", &["n0"], PROBE_URL),
            group_of("Fallback", &["n1", "n0"], PROBE_URL),
            group_of("Other", &["n0"], "http://other.test/generate_204"),
        ],
    );
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| {
        ["Auto", "HK", "Fallback", "Other"]
            .iter()
            .all(|group| routed.group_checked(group))
    })
    .await;
    // n0: once for the three groups sharing a URL, once for the other URL.
    assert_eq!(nodes["n0"].dials.load(Ordering::SeqCst), 2);
    assert_eq!(nodes["n1"].dials.load(Ordering::SeqCst), 1);
    // Every group took the shared result.
    for group in routed.groups() {
        for member in &group.members {
            assert!(
                member.latency_ms.is_some(),
                "{} {} has no latency",
                group.id,
                member.name
            );
        }
    }
    checks.abort();
}

#[tokio::test]
async fn health_checks_run_a_bounded_number_of_probes_at_once() {
    let gauge = Arc::new(Gauge::default());
    let nodes = slow_nodes(100, &gauge);
    let ids: Vec<String> = nodes.keys().cloned().collect();
    let members: Vec<&str> = ids.iter().map(String::as_str).collect();
    let routed = routed_over(
        &nodes,
        vec![
            group_of("Auto", &members, PROBE_URL),
            group_of("Fallback", &members, PROBE_URL),
        ],
    );
    let checks = tokio::spawn(routed.clone().run_health_checks());
    eventually(|| routed.group_checked("Auto") && routed.group_checked("Fallback")).await;
    let peak = gauge.peak.load(Ordering::SeqCst);
    assert!(
        peak <= engine_embedded::routing::MAX_CONCURRENT_PROBES,
        "{peak} probes at once"
    );
    for node in nodes.values() {
        assert_eq!(node.dials.load(Ordering::SeqCst), 1);
    }
    checks.abort();
}
