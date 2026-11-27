//! The embedded engine's side of the mesh engine (`mesh-status.md`,
//! 隧道生命周期): each runtime builds its `"type": "mesh"` outbounds bound to
//! the process's [`EngineSlot`], commits the networks of its profile once
//! its tunnel runs, and holds the mesh engine until it stops. A new profile
//! takes the engine over within the grace period, so networks whose
//! settings did not change keep their sessions; `mesh_engine_stop` lets go
//! at once when the user closes the VPN.
//!
//! Delay tests and checkups build their outbounds from the default registry,
//! whose mesh factory is detached: their mesh outbounds answer
//! `unsupported` and never start or replace a network.
//!
//! The `mesh_*` commands of `mesh-status.md` reach the engine through any
//! runtime's control channel ([`outbound_mesh::outbound::control`]).
//! `mesh_save_network` and `mesh_join` start the engine when none runs; the
//! runtime that answered them then holds it until it stops, so that a
//! network saved while only the proxy runs keeps running.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use engine_outbound::registry::OutboundRegistry;
use outbound_mesh::dns::message::Transport;
use outbound_mesh::outbound::control;
use outbound_mesh::outbound::engine::{EngineHold, EngineSlot, MeshEngine, GRACE};
use outbound_mesh::outbound::MeshFactory;
use outbound_mesh::{IpNet, MeshSettings, TYPE_NAME};
use serde_json::{json, Value};

use crate::config::OutboundConfig;
use crate::routing::RoutedOutbound;
use crate::{RuntimeError, RuntimeErrorCode};

/// The mesh engine of this process.
static SLOT: EngineSlot = EngineSlot::new(GRACE);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One runtime's link to the mesh engine.
#[derive(Default)]
pub(crate) struct MeshBinding {
    /// The settings of every mesh outbound the runtime's profile built.
    built: Arc<Mutex<Vec<MeshSettings>>>,
    /// Held from the tunnel's start to its stop.
    hold: Mutex<Option<EngineHold>>,
    /// Set once the runtime stopped: no command makes it hold the engine
    /// again, so that a host that stopped the tunnel but keeps the runtime
    /// cannot keep the mesh running with the VPN closed.
    stopped: AtomicBool,
}

/// The registry of an engine a runtime looked up for a command.
struct Engine(Arc<MeshEngine>);

impl std::ops::Deref for Engine {
    type Target = outbound_mesh::outbound::registry::Registry;

    fn deref(&self) -> &Self::Target {
        self.0.registry()
    }
}

impl MeshBinding {
    /// `registry` with its mesh factory bound to the engine, when it has
    /// one: a registry without mesh support stays without it.
    pub(crate) fn bind(&self, registry: &OutboundRegistry) -> OutboundRegistry {
        let mut bound = registry.clone();
        if bound.contains(TYPE_NAME) {
            bound.register(Arc::new(MeshFactory::bound(&SLOT, self.built.clone())));
        }
        bound
    }

    /// Commits the profile's networks, after the tunnel started: the
    /// profile is adopted only then. A profile without mesh outbounds
    /// stops the networks of the previous one (unless saved with
    /// `mesh_save_network`) without holding the engine.
    ///
    /// Only the runtime of the profile the user runs may call it: a
    /// runtime started for anything else in the same process (a
    /// diagnostic, say) would stop every network that profile did not
    /// list, and saved networks that carry another device ID than its
    /// own (saved networks without an ID keep running). Today only the
    /// iOS bridge creates runtimes, one per profile.
    pub(crate) fn commit(&self) {
        // The tunnel runs (again): a runtime started after a stop may hold
        // the engine once more.
        self.stopped.store(false, Ordering::SeqCst);
        let networks = lock(&self.built).clone();
        // A profile without mesh outbounds, `allow_mesh: false` among them,
        // commits the empty list: unsaved networks of an earlier profile
        // stop.
        if networks.is_empty() {
            if let Some(engine) = SLOT.current() {
                engine.registry().commit(Vec::new());
            }
            return;
        }
        let mut hold = lock(&self.hold);
        if hold.is_none() {
            // Without a thread for the engine the mesh outbounds report
            // that it is not running; the tunnel runs regardless.
            *hold = SLOT.acquire().ok();
        }
        if let Some(hold) = &*hold {
            let engine = hold.engine();
            engine.registry().commit(networks);
            // The tunnel started: this machine's networks are read again.
            if !engine.read_local_networks(Arc::new(local_networks)) {
                engine.reread_local_networks();
            }
        }
    }

    /// Lets go of the engine when the tunnel stops: it stops after the
    /// grace period unless another profile takes it over.
    pub(crate) fn release(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        lock(&self.hold).take();
    }

    /// Sends the flows to every address a joined mesh network routes
    /// (its `tunnel.routes`) to that network's node of `outbounds`, ahead
    /// of the rules and of every mode. A network the profile has no node
    /// for is left to the rules.
    pub(crate) fn route(
        &self,
        routed: &RoutedOutbound,
        outbounds: &BTreeMap<String, OutboundConfig>,
    ) {
        let tags = mesh_tags(outbounds);
        if tags.is_empty() {
            return;
        }
        let networks: BTreeSet<String> = tags.keys().cloned().collect();
        routed.set_mesh_routes(Arc::new(move |address: IpAddr| {
            let engine = SLOT.current()?;
            let network = engine.registry().network_for(address)?;
            tags.get(&network).cloned()
        }));
        // The intranet names of the same networks: their addresses then
        // go to those nodes too.
        routed.set_mesh_dns(Arc::new(move |message: &[u8]| {
            let engine = SLOT.current()?;
            engine
                .registry()
                .answer_dns(message, Transport::Udp, |network| {
                    networks.contains(network)
                })
        }));
    }

    /// Reads this machine's interface networks again for the mesh
    /// networks (spec §15.4), on the mesh engine's thread: an advertised
    /// subnet that overlaps one is not routed into the mesh. The engine
    /// also reads them every 30 seconds (every 5 until a read succeeds);
    /// the client's network change asks for a read at once.
    fn refresh_local_networks(&self) {
        if let Some(engine) = SLOT.current() {
            engine.reread_local_networks();
        }
    }

    /// Answers a `mesh_*` request; `None` for any other request.
    ///
    /// `{"cmd": "mesh_engine_stop"}`: the user closed the VPN; lets go of
    /// the engine and stops it at once unless another runtime holds it
    /// (`stopped` says whether it stopped).
    pub(crate) fn control(&self, request: &[u8]) -> Option<Result<Vec<u8>, RuntimeError>> {
        // The client reports a network change: the interface networks are
        // read again, and the request goes on to the engine's own handler.
        // Cheap test before parsing: both commands end in `_network`; a
        // name written with JSON escapes is not recognised, and the
        // periodic read catches up with the change.
        if crate::control::names(request, b"_network")
            && matches!(
                crate::control::command_name(request).as_deref(),
                Some("set_network" | "reset_network")
            )
        {
            self.refresh_local_networks();
            return None;
        }
        // Cheap test before parsing: every mesh command names itself.
        if !crate::control::names(request, b"mesh_") {
            return None;
        }
        let name = crate::control::command_name(request)?;
        if name == "mesh_engine_stop" {
            if let Some(hold) = lock(&self.hold).take() {
                hold.close();
            }
            let stopped = SLOT.current().is_none();
            return Some(encode(&json!({"ok": true, "stopped": stopped})));
        }
        let request = control::parse(request)?;
        // The engine is looked up once the arguments are checked: a
        // malformed `mesh_save_network` starts nothing.
        let answer = control::answer_with(request, |starts| {
            if !starts {
                return SLOT.current().map(Engine);
            }
            // The engine this runtime held stopped meanwhile (the user
            // closed the VPN through another runtime): start a new one,
            // once.
            let engine = match self.engine() {
                Some(engine) if engine.is_stopped() => {
                    lock(&self.hold).take();
                    self.engine()
                }
                engine => engine,
            };
            engine.map(Engine)
        });
        Some(encode(&answer))
    }

    /// The running engine, started and held by this runtime when none runs
    /// or this runtime does not hold it yet; `None` when it cannot start or
    /// the runtime stopped.
    fn engine(&self) -> Option<Arc<MeshEngine>> {
        if self.stopped.load(Ordering::SeqCst) {
            return None;
        }
        let mut hold = lock(&self.hold);
        if hold.is_none() {
            *hold = SLOT.acquire().ok();
        }
        let engine = hold.as_ref().map(|hold| hold.engine().clone())?;
        // A network saved while only the proxy runs needs them too.
        engine.read_local_networks(Arc::new(local_networks));
        Some(engine)
    }
}

/// The node id of each mesh network in `outbounds`, by `network.name`;
/// the first id wins when two nodes name one network.
fn mesh_tags(outbounds: &BTreeMap<String, OutboundConfig>) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    for (id, outbound) in outbounds {
        if outbound.kind != TYPE_NAME || outbound.via.is_some() {
            continue;
        }
        let name = outbound
            .settings
            .get("network")
            .and_then(|network| network.get("name"))
            .and_then(Value::as_str);
        if let Some(name) = name {
            tags.entry(name.to_string()).or_insert_with(|| id.clone());
        }
    }
    tags
}

/// The networks of this machine's interfaces but loopback and the tunnel's
/// own, with their prefix lengths; `None` when they cannot be read, so that
/// no advertised subnet is routed into the mesh until a read succeeds (spec
/// §15.4). The tunnel's interface is the one that carries any of `own`, the
/// mesh networks' virtual addresses: until the client has given it those
/// addresses, its other address ranges count as this machine's (an
/// advertised subnet overlapping them stays local; `mesh-status.md`). A
/// network wider than /8 or /7 (such as a missing or empty mask) is left
/// out.
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
))]
fn local_networks(own: &[IpAddr]) -> Option<Vec<IpNet>> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn prefix_of(mask: &[u8]) -> u8 {
        let ones: u32 = mask.iter().map(|byte| byte.count_ones()).sum();
        u8::try_from(ones).unwrap_or(u8::MAX)
    }

    /// `N` bytes of a socket address from getifaddrs, from byte `offset`
    /// on. Apple systems may hand out a mask shorter than its family's
    /// address: the bytes past its `sa_len` read as zero.
    fn bytes<const N: usize>(address: *const libc::sockaddr, offset: usize) -> [u8; N] {
        let mut out = [0u8; N];
        // SAFETY: a socket address from getifaddrs is valid for its length
        // (`sa_len` on Apple systems, its family's size elsewhere), which
        // the caller picked `offset + N` within.
        unsafe {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            let length = usize::from((*address).sa_len);
            #[cfg(not(any(target_os = "ios", target_os = "macos")))]
            let length = offset + N;
            if length > offset {
                std::ptr::copy_nonoverlapping(
                    address.cast::<u8>().add(offset),
                    out.as_mut_ptr(),
                    (length - offset).min(N),
                );
            }
        }
        out
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    // Every address of an interface that is up, but loopback, with the
    // interface's name.
    let mut found: Vec<(String, IpAddr, u8)> = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` points into the list getifaddrs returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        if entry.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0
            || entry.ifa_flags & (libc::IFF_UP as libc::c_uint) == 0
        {
            continue;
        }
        // SAFETY: a non-null name from getifaddrs is a C string.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: a non-null address from getifaddrs.
        let family = libc::c_int::from(unsafe { (*entry.ifa_addr).sa_family });
        // The IPv4 address sits at byte 4 of `sockaddr_in`, the IPv6 one at
        // byte 8 of `sockaddr_in6`.
        let address = match family {
            libc::AF_INET => Some((
                IpAddr::V4(Ipv4Addr::from(bytes::<4>(entry.ifa_addr, 4))),
                prefix_of(&bytes::<4>(entry.ifa_netmask, 4)),
            )),
            libc::AF_INET6 => {
                let mut address = bytes::<16>(entry.ifa_addr, 8);
                // Apple kernels keep the scope of a link-local address in
                // bytes 2 and 3.
                if address[0] == 0xfe && address[1] & 0xc0 == 0x80 {
                    address[2] = 0;
                    address[3] = 0;
                }
                Some((
                    IpAddr::V6(Ipv6Addr::from(address)),
                    prefix_of(&bytes::<16>(entry.ifa_netmask, 8)),
                ))
            }
            _ => None,
        };
        found.extend(address.map(|(address, prefix)| (name, address, prefix)));
    }
    // SAFETY: `head` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Some(interface_networks(found, own))
}

/// The networks of `found` (interface name, address, prefix length) but
/// those of an interface that carries any of `own`, and those wider than
/// /8 (IPv4) or /7 (IPv6). A physical interface that carries one of the
/// mesh addresses (an address conflict) is left out whole, like the
/// tunnel's.
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
))]
fn interface_networks(found: Vec<(String, IpAddr, u8)>, own: &[IpAddr]) -> Vec<IpNet> {
    let tunnel: std::collections::BTreeSet<&str> = found
        .iter()
        .filter(|(_, address, _)| own.contains(address))
        .map(|(name, _, _)| name.as_str())
        .collect();
    found
        .iter()
        .filter(|(name, address, prefix)| {
            // Wider than /8 or /7 (a default route split in halves or
            // quarters, an empty mask): not a network of this machine
            // (spec §15.4 leaves out prefixes shorter than /8 and /7).
            let widest = if address.is_ipv4() { 8 } else { 7 };
            *prefix >= widest && !tunnel.contains(name.as_str())
        })
        .filter_map(|(_, address, prefix)| IpNet::new(*address, *prefix))
        .collect()
}

#[cfg(not(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
)))]
fn local_networks(_own: &[IpAddr]) -> Option<Vec<IpNet>> {
    None
}

fn encode(answer: &Value) -> Result<Vec<u8>, RuntimeError> {
    serde_json::to_vec(answer).map_err(|_| {
        RuntimeError::new(
            RuntimeErrorCode::InternalError,
            "mesh answer could not be encoded",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TcpDialer;

    fn outbound_settings(address: &str) -> engine_outbound::registry::Settings {
        json!({
            "config_version": 1,
            "network": {"name": "embedded-office", "secret": "s3cr3t", "kind": "legacy"},
            "node": {"address": address, "role": "access"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn a_mesh_command_longer_than_the_limit_goes_on_to_the_other_handlers() {
        // Refused for its length there; the engine is never looked up.
        let head = r#"{"cmd":"mesh_status","pad":""#;
        let length = crate::control::MAX_RELOAD_REQUEST_LEN + 1;
        let request = format!("{head}{}\"}}", "x".repeat(length - head.len() - 2));
        assert_eq!(request.len(), length);
        assert!(MeshBinding::default().control(request.as_bytes()).is_none());
    }

    #[test]
    fn mesh_nodes_are_found_by_network_name() {
        let outbounds: BTreeMap<String, OutboundConfig> = serde_json::from_value(json!({
            "mesh-b": {"type": "mesh", "network": {"name": "office"}},
            "mesh-a": {"type": "mesh", "network": {"name": "office"}},
            "mesh-c": {"type": "mesh", "network": {"name": "lab"}},
            "chained": {"type": "mesh", "network": {"name": "home"}, "via": "proxy"},
            "proxy": {"type": "socks", "network": {"name": "home"}},
        }))
        .unwrap();
        let tags = mesh_tags(&outbounds);
        assert_eq!(
            tags,
            BTreeMap::from([
                ("lab".to_string(), "mesh-c".to_string()),
                ("office".to_string(), "mesh-a".to_string()),
            ])
        );
    }

    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "linux",
        target_os = "android"
    ))]
    #[test]
    fn the_tunnels_interface_and_empty_masks_are_left_out() {
        let found = |name: &str, address: &str, prefix: u8| {
            (name.to_owned(), address.parse::<IpAddr>().unwrap(), prefix)
        };
        let networks = super::interface_networks(
            vec![
                found("en0", "192.168.1.20", 24),
                found("en0", "fe80::1", 64),
                // The tunnel: it carries a mesh address, so its other
                // ranges go too.
                found("utun4", "10.157.0.2", 24),
                found("utun4", "fd00:4e43::1", 64),
                found("utun4", "172.19.0.1", 30),
                // An empty mask (an Apple `sa_len` of 0).
                found("en1", "10.0.0.5", 0),
                found("en1", "10.0.0.5", 7),
                found("en1", "fd00::5", 6),
                found("en2", "10.0.0.6", 8),
            ],
            &["10.157.0.2".parse().unwrap()],
        );
        assert_eq!(
            networks,
            [
                IpNet::new("192.168.1.20".parse().unwrap(), 24).unwrap(),
                IpNet::new("fe80::1".parse().unwrap(), 64).unwrap(),
                IpNet::new("10.0.0.6".parse().unwrap(), 8).unwrap(),
            ]
        );
        // Real interfaces can be read here.
        assert!(super::local_networks(&[]).is_some());
    }

    /// One test for the process's engine slot, so that no other test
    /// shares it.
    #[test]
    fn a_profile_commits_its_networks_and_closing_the_vpn_stops_them() {
        // The default registry (delay tests, checkups) builds nothing that
        // reaches a network, and starts nothing.
        let detached = crate::protocols::default_registry();
        let _ = detached
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        assert!(SLOT.current().is_none());

        let first = MeshBinding::default();
        let registry = first.bind(&detached);
        registry
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        // Built, not adopted.
        assert!(SLOT.current().is_none());
        first.commit();
        let engine = SLOT.current().expect("the engine runs");
        // A network change asks the engine for a read of this machine's
        // networks and goes on to the engine's own handler.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while engine.local_reads() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let before = engine.local_reads();
        assert!(before > 0, "the tunnel's start reads them");
        assert!(first
            .control(br#"{"cmd":"set_network","type":"wifi"}"#)
            .is_none());
        while engine.local_reads() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            engine.local_reads() > before,
            "set_network reads them again"
        );
        // The profile's mesh node takes the network's addresses ahead of
        // the rules; other addresses stay with the rules.
        let spec = config_core::routing::RoutingSpec {
            rules: vec!["FINAL,DIRECT".to_string()],
            groups: Vec::new(),
        };
        let direct: Arc<dyn engine_outbound::TcpOutbound> =
            Arc::new(crate::direct::DirectOutbound::new(Arc::new(TcpDialer)));
        let routed = RoutedOutbound::new(
            &spec,
            direct.clone(),
            BTreeMap::from([("mesh-office".to_string(), direct)]),
        )
        .unwrap();
        let outbounds: BTreeMap<String, OutboundConfig> = serde_json::from_value(json!({
            "mesh-office": {"type": "mesh", "network": {"name": "embedded-office"}},
        }))
        .unwrap();
        first.route(&routed, &outbounds);
        let inside = engine_outbound::TargetAddr::Ip("10.160.0.9:22".parse().unwrap());
        let (route, _) = routed.mesh_flow(&inside).expect("routed to the mesh");
        assert_eq!(route.rule, crate::routing::MESH_RULE);
        assert_eq!(route.outbound, "mesh-office");
        let outside = engine_outbound::TargetAddr::Ip("192.0.2.1:22".parse().unwrap());
        assert!(routed.mesh_flow(&outside).is_none());
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs");

        // The next profile keeps the network as it is, whichever runtime
        // stops first.
        let second = MeshBinding::default();
        second
            .bind(&detached)
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        first.release();
        second.commit();
        // A stopped runtime does not hold the engine again.
        let refused: Value = serde_json::from_slice(
            &first
                .control(
                    json!({"cmd": "mesh_join", "network": "embedded-office"})
                        .to_string()
                        .as_bytes(),
                )
                .expect("a mesh command")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused["error"]["code"], "engine_unavailable");
        assert!(lock(&first.hold).is_none());
        assert!(first.control(br#"["mesh_engine_stop"]"#).is_none());
        assert!(!instance.is_retired());
        assert!(Arc::ptr_eq(
            &instance,
            engine.registry().networks()[0].instance.as_ref().unwrap()
        ));

        // A request for another command is not the mesh's.
        assert!(second.control(br#"{"cmd":"traffic"}"#).is_none());

        // The mesh commands reach the engine through any runtime.
        let ask = |binding: &MeshBinding, request: Value| -> Value {
            let answer = binding
                .control(request.to_string().as_bytes())
                .expect("a mesh command")
                .unwrap();
            serde_json::from_slice(&answer).unwrap()
        };
        let status = ask(&first, json!({"cmd": "mesh_status"}));
        assert_eq!(status["network"]["id"], "embedded-office");
        let left = ask(
            &first,
            json!({"cmd": "mesh_leave", "network": "embedded-office"}),
        );
        assert_eq!(left, json!({"ok": true}));
        assert!(instance.is_retired());
        // A later profile does not join it again.
        second.commit();
        let status = ask(&second, json!({"cmd": "mesh_status"}));
        assert_eq!(status["network"]["state"], "not_joined");
        let joined = ask(
            &second,
            json!({"cmd": "mesh_join", "network": "embedded-office"}),
        );
        assert_eq!(joined, json!({"ok": true}));
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs again");
        let unsupported = ask(&second, json!({"cmd": "mesh_set_paths", "network": "x"}));
        assert_eq!(unsupported["error"]["code"], "unsupported");

        // A profile whose networks name different device IDs is refused
        // when built; building does not look at the running networks.
        let mut other = outbound_settings("10.161.0.2/24");
        other.insert(
            "network".into(),
            json!({"name": "lab", "secret": "s3cr3t", "kind": "legacy"}),
        );
        other.insert(
            "node".into(),
            json!({"address": "10.161.0.2/24", "role": "access", "instance_id": "device-2"}),
        );
        let third = MeshBinding::default();
        let registry = third.bind(&detached);
        assert!(registry
            .build(TYPE_NAME, &other, Arc::new(TcpDialer))
            .is_ok());
        assert!(registry
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer)
            )
            .is_err());
        lock(&third.built).clear();
        // The user closes the VPN: the engine stops at once.
        let answer = second.control(br#"{"cmd":"mesh_engine_stop"}"#).unwrap();
        let answer: Value = serde_json::from_slice(&answer.unwrap()).unwrap();
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());
        assert!(instance.is_retired());
        assert!(SLOT.current().is_none());

        // Saving a network starts the engine; the runtime that answered
        // holds it until it lets go.
        let status = ask(&third, json!({"cmd": "mesh_status"}));
        assert_eq!(status["networks"], json!([]));
        assert!(SLOT.current().is_none());
        let saved = ask(
            &third,
            json!({"cmd": "mesh_save_network", "config": Value::Object(outbound_settings("10.160.0.2/24"))}),
        );
        assert_eq!(saved, json!({"ok": true}));
        let engine = SLOT.current().expect("saving started the engine");
        let answer = ask(&third, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());

        // A malformed config is refused before the engine is looked at:
        // it starts nothing, and a stopped runtime refuses it alike.
        let mut bad = outbound_settings("10.160.0.2/24");
        bad.insert(
            "node".into(),
            json!({"address": "not an address", "role": "access"}),
        );
        let save_bad = json!({"cmd": "mesh_save_network", "config": Value::Object(bad)});
        for binding in [&third, &first] {
            let refused = ask(binding, save_bad.clone());
            assert_eq!(refused["error"]["code"], "invalid_argument");
            assert!(SLOT.current().is_none());
        }

        // The new profile starts before the old one stops: the network
        // keeps running.
        let fourth = MeshBinding::default();
        let fifth = MeshBinding::default();
        for binding in [&fourth, &fifth] {
            binding
                .bind(&detached)
                .build(
                    TYPE_NAME,
                    &outbound_settings("10.160.0.2/24"),
                    Arc::new(TcpDialer),
                )
                .unwrap();
        }
        fourth.commit();
        let engine = SLOT.current().expect("the engine runs");
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs");
        fifth.commit();
        fourth.release();
        assert!(!instance.is_retired());
        assert!(Arc::ptr_eq(
            &instance,
            engine.registry().networks()[0].instance.as_ref().unwrap()
        ));

        // A profile without mesh outbounds stops the networks it does not
        // list, without holding the engine.
        let proxy_only = MeshBinding::default();
        proxy_only.commit();
        assert!(instance.is_retired());
        assert!(engine.registry().networks().is_empty());
        assert!(lock(&proxy_only.hold).is_none());
        assert!(!engine.is_stopped());

        // A runtime whose tunnel starts again after a stop holds the
        // engine again, and its commands may start networks.
        fourth.commit();
        assert!(lock(&fourth.hold).is_some());
        let left = ask(
            &fourth,
            json!({"cmd": "mesh_leave", "network": "embedded-office"}),
        );
        assert_eq!(left, json!({"ok": true}));
        let joined = ask(
            &fourth,
            json!({"cmd": "mesh_join", "network": "embedded-office"}),
        );
        assert_eq!(joined, json!({"ok": true}));
        // Another runtime still holds the engine: closing one does not
        // stop it; closing the last does.
        let answer = ask(&fourth, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": false}));
        let answer = ask(&fifth, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());
    }
}
