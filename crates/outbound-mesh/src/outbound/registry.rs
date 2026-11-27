//! The networks of one [`MeshEngine`](super::engine::MeshEngine): which
//! settings the engine adopted for each network, its running instance, and
//! what the user did to it (`mesh_leave`, `mesh_save_network`, a subnet
//! route override).
//!
//! Building an outbound never changes the registry: a delay test, a checkup
//! or a draft profile builds outbounds without stopping a running network.
//! Only [`Registry::commit`], once the engine adopted a profile, and the
//! `mesh_*` commands change it. Every instance runs its driver on the
//! engine's own runtime, never on the caller's.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use ring::rand::SystemRandom;
use tokio::runtime::Handle;
use tokio::sync::watch;

use super::same_settings;
use super::stack::{Failure, Instance};
use crate::claims::HostRoutes;
use crate::config::NetworkKind;
use crate::secure::noise::KeyPair;
use crate::{IpNet, MeshSettings};

/// One network the engine knows.
struct Network {
    /// The settings adopted last, from a profile or `mesh_save_network`,
    /// whichever came later.
    settings: MeshSettings,
    /// The running instance; `None` while the network is left or could
    /// not start.
    instance: Option<Arc<Instance>>,
    /// Why the network could not start, when it could not.
    failure: Option<Failure>,
    /// Cleared by `mesh_leave`, set by `mesh_join`. A profile adopted again
    /// does not join a network the user left.
    joined: bool,
    /// Kept by `mesh_save_network` although no profile lists it.
    saved: bool,
    /// Subnets the user routes through the mesh although they overlap a
    /// network of this machine (`mesh_set_subnet_route`).
    route_overrides: Vec<IpNet>,
    /// The instance's name in the shared [`HostRoutes`]: one per instance,
    /// so that a replaced instance cannot release its successor's claim.
    owner: String,
}

impl Network {
    /// Retires the instance, if any, and frees what it held in `claims` at
    /// once: its addresses go back to the rules.
    fn stop(&mut self, claims: &HostRoutes) {
        if let Some(instance) = self.instance.take() {
            instance.retire();
            claims.release(&self.owner);
        }
    }
}

#[derive(Default)]
struct Inner {
    networks: BTreeMap<String, Network>,
    /// Static keys made for networks configured without
    /// `node.private_key` (`legacy` only), one per network for as long as
    /// the registry knows the network: a restart of the network keeps its
    /// key (spec §8.1).
    keys: BTreeMap<String, KeyPair>,
    /// The engine stopped; nothing starts any more.
    closed: bool,
    /// The `tunnel.routes` last reported and their `routesVersion`.
    routes: (Vec<IpNet>, u64),
}

/// What [`Registry::network`] reports about one network.
#[derive(Clone)]
pub struct NetworkState {
    pub settings: MeshSettings,
    pub joined: bool,
    /// Kept by `mesh_save_network`.
    pub saved: bool,
    pub instance: Option<Arc<Instance>>,
    pub failure: Option<Failure>,
    /// `mesh_set_subnet_route` overrides.
    pub route_overrides: Vec<IpNet>,
}

/// Why a command could not change the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// No network of that name.
    NotFound,
    /// The engine stopped.
    Closed,
    /// `mesh_save_network` of a `managed` network without
    /// `node.private_key` (`mesh-module.md`): refused, not stored.
    PrivateKeyRequired,
    /// `node.instance_id` differs from that of another network: one device
    /// has one instance ID (`mesh-module.md`).
    InstanceIdMismatch,
    /// `mesh_set_subnet_route` beyond [`MAX_ROUTE_OVERRIDES`].
    TooManyOverrides,
}

/// Most `mesh_set_subnet_route` overrides kept for one network.
pub const MAX_ROUTE_OVERRIDES: usize = 256;

impl RegistryError {
    /// The `error.code` and `error.detail` of a refused command
    /// (`mesh-status.md`, 命令).
    pub fn answer(self) -> (&'static str, &'static str) {
        match self {
            Self::NotFound => ("not_found", "no saved mesh network of that name"),
            Self::Closed => ("engine_unavailable", "the mesh engine is not running"),
            Self::PrivateKeyRequired => (
                "invalid_argument",
                "private_key_required: a managed network needs node.private_key",
            ),
            Self::InstanceIdMismatch => (
                "invalid_argument",
                "node.instance_id differs from that of another mesh network",
            ),
            Self::TooManyOverrides => (
                "invalid_argument",
                "the network already has 256 subnet route overrides",
            ),
        }
    }
}

pub struct Registry {
    runtime: Handle,
    inner: Mutex<Inner>,
    /// What each running network routes, shared by all (spec §15.4, 同一
    /// 进程中的多个网络): flows are routed by it ([`Self::network_for`]).
    claims: HostRoutes,
    /// The networks of this machine's interfaces; `None` until read once.
    machine: watch::Sender<Option<Vec<IpNet>>>,
    /// Numbers the instances' owners in [`Self::claims`].
    owners: AtomicU64,
}

impl Registry {
    /// An empty registry whose networks run on `runtime`.
    pub fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            inner: Mutex::new(Inner::default()),
            claims: HostRoutes::reclaiming(),
            machine: watch::channel(None).0,
            owners: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adopts the mesh networks of a profile the engine took on. A network
    /// whose settings did not change keeps running with its sessions; a
    /// changed one is replaced; one the profile no longer lists stops,
    /// unless `mesh_save_network` kept it. A network the user left stays
    /// left. Never fails: a network that cannot start records why, and the
    /// profile stays adopted.
    pub fn commit(&self, profile: Vec<MeshSettings>) {
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        let mut listed: Vec<String> = Vec::new();
        let profile_id = profile
            .first()
            .and_then(|settings| settings.instance_id.clone());
        for settings in profile {
            // The same network twice in one profile: the first counts, so
            // that the second does not replace it at once.
            if listed.contains(&settings.network_name) {
                continue;
            }
            listed.push(settings.network_name.clone());
            self.put(&mut inner, settings, false);
        }
        // The profile names this device's instance ID: a saved network the
        // profile does not list and that carries another one (saved before
        // the client changed it) stops, not run under a second identity,
        // and reports `instance_id_changed` until `mesh_save_network` gives
        // it the current ID or a profile names its ID again. A profile
        // without an ID leaves every saved network as it is, and a saved
        // network without an ID is left as it is by every profile.
        if let Some(id) = profile_id {
            let Inner { networks, keys, .. } = &mut *inner;
            for (name, network) in networks.iter_mut() {
                if !network.saved || listed.contains(name) || !network.joined {
                    continue;
                }
                // A network without an ID runs under none of the device's:
                // it conflicts with no profile, as with `mesh_join`.
                let Some(own) = network.settings.instance_id.as_deref() else {
                    continue;
                };
                if own != id {
                    network.failure = Some(Failure::InstanceIdChanged);
                    network.stop(&self.claims);
                } else if network.failure == Some(Failure::InstanceIdChanged) {
                    self.start(keys, network);
                }
            }
        }
        let gone: Vec<String> = inner
            .networks
            .iter()
            .filter(|(name, network)| !network.saved && !listed.contains(name))
            .map(|(name, _)| name.clone())
            .collect();
        for name in gone {
            // Its key stays: the network may come back in a later profile
            // and should keep its identity (spec §8.1).
            if let Some(mut network) = inner.networks.remove(&name) {
                network.stop(&self.claims);
            }
        }
    }

    /// `mesh_save_network`: adopts `settings` as a profile would, and keeps
    /// the network although later profiles do not list it.
    pub fn save(&self, settings: MeshSettings) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
        }
        if settings.kind == NetworkKind::Managed && settings.private_key.is_none() {
            return Err(RegistryError::PrivateKeyRequired);
        }
        if conflicting_instance_id(&inner, &settings) {
            return Err(RegistryError::InstanceIdMismatch);
        }
        self.put(&mut inner, settings, true);
        Ok(())
    }

    /// The `routesVersion` of `routes` (snapshot `tunnel`): 1 for the
    /// first routes reported, one more at each change.
    pub fn routes_version(&self, routes: &[IpNet]) -> u64 {
        let mut inner = self.lock();
        let (last, version) = &mut inner.routes;
        if *version == 0 || last.as_slice() != routes {
            *last = routes.to_vec();
            *version += 1;
        }
        *version
    }

    /// `mesh_join`: starts a network the user left, or one that could not
    /// start before.
    pub fn join(&self, name: &str) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
        }
        let settings = &inner
            .networks
            .get(name)
            .ok_or(RegistryError::NotFound)?
            .settings;
        if conflicting_instance_id(&inner, settings) {
            return Err(RegistryError::InstanceIdMismatch);
        }
        let inner = &mut *inner;
        let network = inner
            .networks
            .get_mut(name)
            .ok_or(RegistryError::NotFound)?;
        network.joined = true;
        let running = network
            .instance
            .as_ref()
            .is_some_and(|instance| !instance.is_retired());
        if !running {
            self.start(&mut inner.keys, network);
        }
        Ok(())
    }

    /// `mesh_leave`: stops the network and keeps it stopped until
    /// `mesh_join`, however often a profile lists it again.
    pub fn leave(&self, name: &str) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
        }
        let network = inner
            .networks
            .get_mut(name)
            .ok_or(RegistryError::NotFound)?;
        network.joined = false;
        network.failure = None;
        network.stop(&self.claims);
        Ok(())
    }

    /// `mesh_remove_network`: stops the network and forgets it, its key
    /// included.
    pub fn remove(&self, name: &str) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
        }
        if !inner.networks.contains_key(name) {
            return Err(RegistryError::NotFound);
        }
        remove(&mut inner, &self.claims, name);
        Ok(())
    }

    /// `mesh_set_subnet_route`: the subnets of `name` routed through the
    /// mesh although they overlap a network of this machine.
    /// `mesh` adds `cidr` to the overrides of `name`, otherwise removes
    /// it; read and written under one lock, at most
    /// [`MAX_ROUTE_OVERRIDES`] per network.
    pub fn set_route_override(
        &self,
        name: &str,
        cidr: IpNet,
        mesh: bool,
    ) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
        }
        let network = inner
            .networks
            .get_mut(name)
            .ok_or(RegistryError::NotFound)?;
        let mut overrides = network.route_overrides.clone();
        overrides.retain(|net| *net != cidr);
        if mesh {
            if overrides.len() >= MAX_ROUTE_OVERRIDES {
                return Err(RegistryError::TooManyOverrides);
            }
            overrides.push(cidr);
        }
        if let Some(instance) = &network.instance {
            instance.set_route_overrides(overrides.clone());
        }
        network.route_overrides = overrides;
        Ok(())
    }

    /// The joined network that routes `address`: the most specific of
    /// every joined network's virtual subnets, running or not, and the
    /// advertised subnets each running network holds (spec §15.4: a
    /// subnet goes to one network only). An address of a network whose
    /// driver does not run thus still goes to that network, and fails
    /// there, rather than on to the rules. The embedded engine sends such
    /// flows to that network ahead of the profile's rules
    /// (`mesh-status.md`). Takes no registry lock.
    pub fn network_for(&self, address: IpAddr) -> Option<String> {
        let owner = self.claims.lookup(address)?;
        Some(network_of(&owner).to_owned())
    }

    /// `tunnel.routes`: every joined network's virtual subnets, then the
    /// advertised subnets it holds, in network order and without repeats.
    pub fn tunnel_routes(&self) -> Vec<IpNet> {
        let inner = self.lock();
        let mut seen = HashSet::new();
        let mut routes = Vec::new();
        for network in inner.networks.values() {
            let live = network.joined
                && network
                    .instance
                    .as_ref()
                    .is_some_and(|instance| !instance.is_retired());
            if !live {
                continue;
            }
            let subnets = network.settings.virtual_subnets();
            for net in subnets.into_iter().chain(self.claims.held(&network.owner)) {
                if seen.insert(net) {
                    routes.push(net);
                }
            }
        }
        routes
    }

    /// The virtual addresses of every network: the tunnel interface that
    /// carries one is this engine's own (spec §15.4).
    pub fn own_addresses(&self) -> Vec<IpAddr> {
        self.lock()
            .networks
            .values()
            .flat_map(|network| network.settings.local_addresses())
            .collect()
    }

    /// The networks of this machine's interfaces read last; `None` before
    /// the first read.
    pub fn local_networks(&self) -> Option<Vec<IpNet>> {
        self.machine.borrow().clone()
    }

    /// The networks of this machine's interfaces, read again. A read that
    /// failed is not reported: the last networks stay (spec §15.4).
    pub fn set_local_networks(&self, networks: Vec<IpNet>) {
        self.machine.send_if_modified(|current| {
            let changed = current.as_ref() != Some(&networks);
            if changed {
                *current = Some(networks);
            }
            changed
        });
    }

    /// The running instance of `name` for an outbound built with
    /// `settings`. Looked up and taken under one lock, so that a commit
    /// cannot hand out an instance it is replacing. An outbound of a draft
    /// profile, whose settings the engine did not adopt, gets no instance
    /// and starts nothing.
    pub fn instance(&self, name: &str, settings: &MeshSettings) -> io::Result<Arc<Instance>> {
        let inner = self.lock();
        if inner.closed {
            return Err(Failure::Stopped.error());
        }
        let network = inner
            .networks
            .get(name)
            .filter(|network| same_settings(&network.settings, settings))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "mesh network is not in the adopted profile",
                )
            })?;
        if !network.joined {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "mesh network was left",
            ));
        }
        match &network.instance {
            Some(instance) => Ok(instance.clone()),
            None => Err(network.failure.unwrap_or(Failure::Stopped).error()),
        }
    }

    /// The state of every network, by name. The settings leave out the
    /// private key.
    pub fn networks(&self) -> Vec<NetworkState> {
        self.lock()
            .networks
            .values_mut()
            .map(|network| NetworkState {
                settings: without_private_key(&mut network.settings),
                joined: network.joined,
                saved: network.saved,
                instance: network.instance.clone(),
                failure: network.failure,
                route_overrides: network.route_overrides.clone(),
            })
            .collect()
    }

    /// Stops every network for good and forgets them; later commits and
    /// commands change nothing.
    pub fn shutdown(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        for (_, mut network) in std::mem::take(&mut inner.networks) {
            network.stop(&self.claims);
        }
        inner.keys.clear();
    }

    /// Adopts `settings` for its network (the later writer wins) and starts
    /// it if it is joined and changed.
    fn put(&self, inner: &mut Inner, settings: MeshSettings, saved: bool) {
        let name = settings.network_name.clone();
        let Inner { networks, keys, .. } = inner;
        match networks.get_mut(&name) {
            Some(network) => {
                network.saved |= saved;
                // A network stopped for its device ID starts again once a
                // profile or `mesh_save_network` adopts it as it is.
                if same_settings(&network.settings, &settings)
                    && network.failure != Some(Failure::InstanceIdChanged)
                {
                    return;
                }
                // The old instance gives way once the new one has joined
                // the claims, so that its addresses never fall to the
                // rules in between.
                let old = network.instance.take();
                let old_owner = std::mem::take(&mut network.owner);
                // A new key in the settings replaces the one made before.
                if settings.private_key.is_some() {
                    keys.remove(&name);
                }
                network.settings = settings;
                network.failure = None;
                if network.joined {
                    self.start(keys, network);
                }
                if let Some(old) = old {
                    old.retire();
                    self.claims.release(&old_owner);
                }
            }
            None => {
                let mut network = Network {
                    settings,
                    instance: None,
                    failure: None,
                    joined: true,
                    saved,
                    route_overrides: Vec::new(),
                    owner: String::new(),
                };
                self.start(keys, &mut network);
                networks.insert(name, network);
            }
        }
    }

    /// Starts `network` on the engine's runtime with its static key.
    fn start(&self, keys: &mut BTreeMap<String, KeyPair>, network: &mut Network) {
        let settings = &network.settings;
        let key = match &settings.private_key {
            Some(private) => KeyPair::from_private_ref(private),
            None if settings.kind == NetworkKind::Managed => {
                network.failure = Some(Failure::PrivateKeyRequired);
                return;
            }
            None => match keys.get(&settings.network_name) {
                Some(key) => key.clone(),
                None => match KeyPair::generate(&SystemRandom::new()) {
                    Ok(key) => {
                        keys.insert(settings.network_name.clone(), key.clone());
                        key
                    }
                    Err(_) => {
                        network.failure = Some(Failure::Stopped);
                        return;
                    }
                },
            },
        };
        let instance = Instance::with_key(settings.clone(), key, Some(self.runtime.clone()));
        // Its virtual subnets are routed to it at once, and no other
        // network may claim them.
        let owner = format!(
            "{}/{}",
            self.owners.fetch_add(1, Ordering::Relaxed),
            settings.network_name
        );
        self.claims.join(
            &owner,
            settings.kind == NetworkKind::Managed,
            &settings.virtual_subnets(),
        );
        instance.set_route_overrides(network.route_overrides.clone());
        instance.start();
        self.runtime.spawn(follow_claims(
            Arc::downgrade(&instance),
            owner.clone(),
            self.claims.clone(),
            self.machine.subscribe(),
        ));
        network.failure = None;
        network.instance = Some(instance);
        network.owner = owner;
    }
}

/// The network name of an owner in [`HostRoutes`] (`<number>/<name>`).
fn network_of(owner: &str) -> &str {
    owner.split_once('/').map_or(owner, |(_, name)| name)
}

/// Releases an owner's claims however its task ends.
struct Release {
    claims: HostRoutes,
    owner: String,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.claims.release(&self.owner);
    }
}

/// Keeps one instance's part of the shared claims current until it
/// retires: it claims the advertised subnets its driver routes while it
/// runs, and it sees as this machine's networks the interfaces' networks
/// and whatever the other networks hold, so that its driver refuses those
/// as local (spec §15.4). Runs again whenever its driver's snapshot, its
/// state, the others' claims or the interfaces' networks change; a change
/// it caused itself settles at once.
async fn follow_claims(
    instance: Weak<Instance>,
    owner: String,
    claims: HostRoutes,
    mut machine: watch::Receiver<Option<Vec<IpNet>>>,
) {
    let _release = Release {
        claims: claims.clone(),
        owner: owner.clone(),
    };
    let (mut snapshots, mut changes) = match instance.upgrade() {
        Some(instance) => (instance.snapshot(), instance.changes()),
        None => return,
    };
    let mut others = claims.subscribe();
    // What the last round claimed with, so that a snapshot that changed
    // something else (most do: counters, latencies) claims nothing anew.
    let mut last_wanted: Option<Vec<IpNet>> = None;
    // The shared claims or this machine's networks changed since the
    // instance was last told its local networks.
    let mut look = true;
    loop {
        {
            let Some(instance) = instance.upgrade() else {
                return;
            };
            if instance.is_retired() {
                return;
            }
            // Nothing is claimed before this machine's networks were read,
            // nor while no driver runs.
            let running = instance.state().0;
            let wanted = {
                let snapshot = snapshots.borrow_and_update();
                let routes: &[IpNet] = if running && snapshot.local_networks_read {
                    &snapshot.system_routes
                } else {
                    &[]
                };
                (last_wanted.as_deref() != Some(routes)).then(|| routes.to_vec())
            };
            if look || wanted.is_some() {
                others.mark_unchanged();
                let wanted = wanted.unwrap_or_else(|| last_wanted.clone().unwrap_or_default());
                claims.claim(&owner, &wanted);
                last_wanted = Some(wanted);
            }
            if look {
                let local = machine.borrow_and_update().clone().map(|mut networks| {
                    networks.extend(claims.others(&owner));
                    networks
                });
                instance.set_local_networks(local);
                look = false;
            }
        }
        tokio::select! {
            changed = snapshots.changed() => if changed.is_err() { return },
            changed = changes.changed() => if changed.is_err() { return },
            _ = others.changed() => look = true,
            _ = machine.changed() => look = true,
        }
    }
}

/// Whether another network that has an instance now carries another
/// device ID than `settings`. A network that is left, or stopped for its
/// ID, does not count: it runs under no identity. A network configured
/// without an ID, of either kind, conflicts with none: the node then has
/// a random one for that network only.
fn conflicting_instance_id(inner: &Inner, settings: &MeshSettings) -> bool {
    let Some(id) = settings.instance_id.as_deref() else {
        return false;
    };
    inner.networks.iter().any(|(name, network)| {
        *name != settings.network_name
            && network
                .instance
                .as_ref()
                .is_some_and(|instance| !instance.is_retired())
            && network
                .settings
                .instance_id
                .as_deref()
                .is_some_and(|other| other != id)
    })
}

/// A copy of `settings` without the private key, which is never copied:
/// its box is set aside while the rest is cloned, then put back.
fn without_private_key(settings: &mut MeshSettings) -> MeshSettings {
    let key = settings.private_key.take();
    let copy = settings.clone();
    settings.private_key = key;
    copy
}

fn remove(inner: &mut Inner, claims: &HostRoutes, name: &str) {
    if let Some(mut network) = inner.networks.remove(name) {
        network.stop(claims);
    }
    inner.keys.remove(name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MeshConfig;
    use serde_json::json;

    fn settings(name: &str, address: &str, kind: &str) -> MeshSettings {
        let config: MeshConfig = serde_json::from_value(json!({
            "config_version": 1,
            "network": {"name": name, "secret": "s3cr3t", "kind": kind},
            "node": {"address": address, "role": "access"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        }))
        .unwrap();
        config.validate().unwrap()
    }

    /// A runtime that is never driven: drivers spawned on it never run, so
    /// the tests open no socket.
    fn registry() -> (tokio::runtime::Runtime, Registry) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let registry = Registry::new(runtime.handle().clone());
        (runtime, registry)
    }

    fn found(registry: &Registry, settings: &MeshSettings) -> Arc<Instance> {
        registry
            .instance(&settings.network_name, settings)
            .expect("the network runs")
    }

    fn with_id(name: &str, address: &str, id: &str) -> MeshSettings {
        let mut settings = settings(name, address, "legacy");
        settings.instance_id = Some(id.into());
        settings
    }

    fn state(registry: &Registry, name: &str) -> NetworkState {
        registry
            .networks()
            .into_iter()
            .find(|network| network.settings.network_name == name)
            .expect("the registry knows the network")
    }

    #[test]
    fn a_profile_with_a_new_device_id_stops_saved_networks_of_the_old_one() {
        let (_runtime, registry) = registry();
        let mut saved = with_id("lab", "10.147.0.2/24", "device-1");
        let home = with_id("home", "10.147.1.2/24", "device-1");
        registry.save(saved.clone()).unwrap();
        registry.save(home.clone()).unwrap();
        let old = found(&registry, &saved);
        let old_home = found(&registry, &home);
        let office = with_id("office", "10.146.0.2/24", "device-2");
        registry.commit(vec![office.clone()]);
        // Both kept, neither run under a second identity, and told apart
        // from a network the user left.
        assert!(old.is_retired() && old_home.is_retired());
        for name in ["lab", "home"] {
            let network = state(&registry, name);
            assert!(network.joined && network.instance.is_none());
            assert_eq!(network.failure, Some(Failure::InstanceIdChanged));
        }
        assert_eq!(Failure::InstanceIdChanged.code(), "instance_id_changed");
        assert!(registry.instance("lab", &saved).is_err());
        found(&registry, &office);
        // Joining it as it is would run a second identity.
        assert_eq!(registry.join("lab"), Err(RegistryError::InstanceIdMismatch));
        // Saved again with the current ID, it runs.
        saved.instance_id = Some("device-2".into());
        registry.save(saved.clone()).unwrap();
        found(&registry, &saved);
        registry.join("lab").unwrap();
        // A saved network of the same ID is not touched by a commit.
        let lab = found(&registry, &saved);
        registry.commit(vec![office]);
        assert!(!lab.is_retired());
        // A profile of the old ID again: the network of that ID runs again,
        // the other one stops.
        registry.commit(vec![with_id("office", "10.146.0.2/24", "device-1")]);
        found(&registry, &home);
        assert!(lab.is_retired());
        assert_eq!(
            state(&registry, "lab").failure,
            Some(Failure::InstanceIdChanged)
        );
    }

    #[test]
    fn a_profile_listing_a_stopped_network_as_it_is_starts_it() {
        let (_runtime, registry) = registry();
        let lab = with_id("lab", "10.147.0.2/24", "device-1");
        registry.save(lab.clone()).unwrap();
        registry.commit(vec![with_id("office", "10.146.0.2/24", "device-2")]);
        assert!(registry.instance("lab", &lab).is_err());
        registry.commit(vec![lab.clone()]);
        found(&registry, &lab);
    }

    #[test]
    fn a_profile_without_a_device_id_leaves_saved_networks_running() {
        let (_runtime, registry) = registry();
        let lab = with_id("lab", "10.147.0.2/24", "device-1");
        registry.save(lab.clone()).unwrap();
        let running = found(&registry, &lab);
        registry.commit(vec![settings("office", "10.146.0.2/24", "legacy")]);
        assert!(!running.is_retired());
        registry.commit(Vec::new());
        assert!(!running.is_retired());
    }

    #[test]
    fn a_network_without_a_device_id_conflicts_with_none() {
        let (_runtime, registry) = registry();
        let lab = with_id("lab", "10.147.0.2/24", "device-1");
        registry.save(lab.clone()).unwrap();
        let office = settings("office", "10.146.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        found(&registry, &lab);
        found(&registry, &office);
        // Both run: commands on either, and a new network of either kind,
        // are not refused for the ID.
        registry.join("lab").unwrap();
        registry.join("office").unwrap();
        registry
            .save(settings("home", "10.147.1.2/24", "legacy"))
            .unwrap();
        registry
            .save(with_id("garage", "10.147.2.2/24", "device-1"))
            .unwrap();
        assert_eq!(
            registry.save(with_id("shed", "10.147.3.2/24", "device-2")),
            Err(RegistryError::InstanceIdMismatch)
        );
    }

    #[test]
    fn a_saved_network_without_a_device_id_keeps_running_under_any_profile() {
        let (_runtime, registry) = registry();
        let home = settings("home", "10.147.1.2/24", "legacy");
        registry.save(home.clone()).unwrap();
        let running = found(&registry, &home);
        registry.commit(vec![with_id("office", "10.146.0.2/24", "device-2")]);
        assert!(!running.is_retired());
        assert_eq!(state(&registry, "home").failure, None);
        registry.commit(vec![with_id("office", "10.146.0.2/24", "device-3")]);
        assert!(Arc::ptr_eq(&running, &found(&registry, &home)));
    }

    #[test]
    fn only_running_networks_count_for_the_device_id() {
        let (_runtime, registry) = registry();
        let lab = with_id("lab", "10.147.0.2/24", "device-1");
        registry.save(lab.clone()).unwrap();
        registry.leave("lab").unwrap();
        // A left network runs under no identity: another ID is taken.
        let home = with_id("home", "10.147.1.2/24", "device-2");
        registry.save(home.clone()).unwrap();
        found(&registry, &home);
        // Joining the left one now would run two identities.
        assert_eq!(registry.join("lab"), Err(RegistryError::InstanceIdMismatch));
        assert!(!state(&registry, "lab").joined);
        registry.leave("home").unwrap();
        registry.join("lab").unwrap();
        found(&registry, &lab);
    }

    #[test]
    fn an_address_is_routed_to_the_joined_network_that_holds_it() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.157.0.2/24", "legacy");
        let lab = settings("lab", "10.157.0.130/25", "legacy");
        let address = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(registry.network_for(address("10.157.0.9")), None);
        registry.commit(vec![office.clone(), lab.clone()]);
        assert_eq!(
            registry.network_for(address("10.157.0.9")).as_deref(),
            Some("office")
        );
        // The more specific route wins.
        assert_eq!(
            registry.network_for(address("10.157.0.200")).as_deref(),
            Some("lab")
        );
        assert_eq!(registry.network_for(address("10.158.0.1")), None);
        assert_eq!(registry.network_for(address("fd00::1")), None);
        // The drivers never run here: a joined network's virtual subnet is
        // routed to it all the same, and fails there rather than going on
        // to the rules. A left network routes nothing.
        registry.leave("lab").unwrap();
        assert_eq!(
            registry.network_for(address("10.157.0.200")).as_deref(),
            Some("office")
        );
        registry.leave("office").unwrap();
        assert_eq!(registry.network_for(address("10.157.0.9")), None);
    }

    #[test]
    fn networks_split_advertised_subnets_and_see_the_others_as_local() {
        use crate::driver::Snapshot;
        use crate::secure::noise::KeyPair;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let claims = HostRoutes::reclaiming();
        let (machine, _) = watch::channel(None);
        let net = |text: &str| IpNet::parse(text).unwrap();
        let address = |text: &str| text.parse::<IpAddr>().unwrap();
        let make = |name: &str, address: &str, kind: &str| {
            let settings = settings(name, address, kind);
            let key = KeyPair::generate(&SystemRandom::new()).unwrap();
            let instance = Instance::with_key(settings.clone(), key, None);
            claims.join(
                name,
                settings.kind == NetworkKind::Managed,
                &settings.virtual_subnets(),
            );
            runtime.spawn(follow_claims(
                Arc::downgrade(&instance),
                name.to_owned(),
                claims.clone(),
                machine.subscribe(),
            ));
            instance
        };
        let settle = || {
            runtime.block_on(async {
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
            })
        };
        let routes = |subnets: &[&str]| Snapshot {
            system_routes: subnets.iter().map(|text| net(text)).collect(),
            local_networks_read: true,
            ..Snapshot::default()
        };
        let office = make("office", "10.157.0.2/24", "legacy");
        let lab = make("lab", "10.160.0.2/24", "legacy");
        settle();
        // Not running: nothing is claimed; this machine's networks are
        // not read yet.
        assert_eq!(office.local_networks(), None);
        assert_eq!(
            claims.lookup(address("10.157.0.9")).as_deref(),
            Some("office")
        );
        machine.send_replace(Some(vec![net("192.168.1.0/24")]));
        office.pretend(routes(&["192.168.10.0/24"]));
        settle();
        assert_eq!(claims.held("office"), [net("192.168.10.0/24")]);
        // The first to claim keeps it; the other sees it as local.
        lab.pretend(routes(&["192.168.10.0/24", "172.16.8.0/24"]));
        settle();
        assert_eq!(claims.held("lab"), [net("172.16.8.0/24")]);
        let local = lab.local_networks().unwrap();
        assert!(local.contains(&net("192.168.1.0/24")));
        assert!(local.contains(&net("192.168.10.0/24")));
        assert!(local.contains(&net("10.157.0.0/24")));
        assert_eq!(
            claims.lookup(address("192.168.10.5")).as_deref(),
            Some("office")
        );
        assert_eq!(claims.lookup(address("172.16.8.5")).as_deref(), Some("lab"));
        // A network that is dropped frees its range; a managed one takes a
        // subnet from a legacy one.
        let gone = make("gone", "10.170.0.2/24", "legacy");
        settle();
        assert_eq!(
            claims.lookup(address("10.170.0.9")).as_deref(),
            Some("gone")
        );
        drop(gone);
        settle();
        assert_eq!(claims.lookup(address("10.170.0.9")), None);
        let hq = {
            let settings = settings("hq", "10.170.0.2/24", "legacy");
            let key = KeyPair::generate(&SystemRandom::new()).unwrap();
            let instance = Instance::with_key(settings.clone(), key, None);
            claims.join("hq", true, &settings.virtual_subnets());
            runtime.spawn(follow_claims(
                Arc::downgrade(&instance),
                "hq".to_owned(),
                claims.clone(),
                machine.subscribe(),
            ));
            instance
        };
        settle();
        assert_eq!(claims.lookup(address("10.170.0.9")).as_deref(), Some("hq"));
        hq.pretend(routes(&["192.168.10.0/24"]));
        settle();
        assert_eq!(claims.held("hq"), [net("192.168.10.0/24")]);
        assert!(claims.held("office").is_empty());
        assert!(office
            .local_networks()
            .unwrap()
            .contains(&net("192.168.10.0/24")));
        assert_eq!(
            claims.lookup(address("192.168.10.5")).as_deref(),
            Some("hq")
        );
        // A retired network frees its addresses.
        lab.retire();
        settle();
        assert_eq!(claims.lookup(address("172.16.8.5")), None);
        assert_eq!(claims.lookup(address("10.160.0.9")), None);
    }

    #[test]
    fn the_routes_version_changes_only_with_the_routes() {
        let (_runtime, registry) = registry();
        let a = [IpNet::parse("10.146.0.0/24").unwrap()];
        let b = [
            IpNet::parse("10.146.0.0/24").unwrap(),
            IpNet::parse("192.168.10.0/24").unwrap(),
        ];
        assert_eq!(registry.routes_version(&[]), 1);
        assert_eq!(registry.routes_version(&[]), 1);
        assert_eq!(registry.routes_version(&a), 2);
        assert_eq!(registry.routes_version(&a), 2);
        assert_eq!(registry.routes_version(&b), 3);
        assert_eq!(registry.routes_version(&a), 4);
    }

    #[test]
    fn the_same_settings_keep_the_running_network() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.146.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        let first = found(&registry, &office);
        registry.commit(vec![office.clone()]);
        assert!(Arc::ptr_eq(&first, &found(&registry, &office)));
        assert!(!first.is_retired());
    }

    #[test]
    fn changed_settings_replace_the_network_and_keep_its_key() {
        let (_runtime, registry) = registry();
        let old = settings("office", "10.147.0.2/24", "legacy");
        let new = settings("office", "10.147.0.3/24", "legacy");
        registry.commit(vec![old.clone()]);
        let first = found(&registry, &old);
        registry.commit(vec![new.clone()]);
        let second = found(&registry, &new);
        assert!(first.is_retired());
        assert_eq!(first.state(), (false, Some(Failure::Replaced)));
        // The same network keeps its key across the restart (spec §8.1).
        assert_eq!(first.static_public_key(), second.static_public_key());
        // An outbound still built with the old settings gets nothing.
        assert!(registry.instance("office", &old).is_err());
    }

    #[test]
    fn building_a_draft_starts_nothing() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.148.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        let running = found(&registry, &office);
        let draft = settings("office", "10.148.0.9/24", "legacy");
        let error = registry
            .instance("office", &draft)
            .err()
            .expect("a draft gets no instance");
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(!running.is_retired());
        assert!(registry.instance("elsewhere", &draft).is_err());
    }

    #[test]
    fn a_network_the_profile_drops_stops_unless_saved() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.149.0.2/24", "legacy");
        let home = settings("home", "10.150.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        registry.save(home.clone()).unwrap();
        let first = found(&registry, &office);
        registry.commit(Vec::new());
        assert!(first.is_retired());
        assert!(registry.instance("office", &office).is_err());
        // Kept by mesh_save_network.
        assert!(registry.instance("home", &home).is_ok());
        // A network that comes back keeps its key.
        registry.commit(vec![office.clone()]);
        assert_eq!(
            first.static_public_key(),
            found(&registry, &office).static_public_key()
        );
        // Removed with mesh_remove_network, it gets a new one.
        registry.remove("office").unwrap();
        registry.commit(vec![office.clone()]);
        assert_ne!(
            first.static_public_key(),
            found(&registry, &office).static_public_key()
        );
    }

    #[test]
    fn the_first_of_two_networks_with_one_name_counts() {
        let (_runtime, registry) = registry();
        let first = settings("office", "10.155.0.2/24", "legacy");
        let second = settings("office", "10.155.0.3/24", "legacy");
        registry.commit(vec![first.clone(), second.clone()]);
        let running = found(&registry, &first);
        assert!(!running.is_retired());
        assert!(registry.instance("office", &second).is_err());
    }

    #[test]
    fn a_left_network_stays_left_until_joined() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.151.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        let first = found(&registry, &office);
        registry.leave("office").unwrap();
        assert!(first.is_retired());
        registry.commit(vec![office.clone()]);
        assert!(registry.instance("office", &office).is_err());
        assert!(!registry.networks()[0].joined);
        registry.join("office").unwrap();
        let again = found(&registry, &office);
        assert_eq!(first.static_public_key(), again.static_public_key());
        assert_eq!(registry.leave("other"), Err(RegistryError::NotFound));
    }

    #[test]
    fn the_later_writer_wins() {
        let (_runtime, registry) = registry();
        let profile = settings("office", "10.152.0.2/24", "legacy");
        let saved = settings("office", "10.152.0.3/24", "legacy");
        registry.commit(vec![profile.clone()]);
        registry.save(saved.clone()).unwrap();
        assert!(registry.instance("office", &profile).is_err());
        assert!(registry.instance("office", &saved).is_ok());
        registry.commit(vec![profile.clone()]);
        assert!(registry.instance("office", &profile).is_ok());
        assert!(registry.instance("office", &saved).is_err());
    }

    #[test]
    fn a_managed_network_without_its_key_does_not_start() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.153.0.2/24", "managed");
        registry.commit(vec![office.clone()]);
        let state = &registry.networks()[0];
        assert!(state.instance.is_none());
        assert_eq!(state.failure, Some(Failure::PrivateKeyRequired));
        assert_eq!(Failure::PrivateKeyRequired.code(), "private_key_required");
        assert!(registry.instance("office", &office).is_err());
        // mesh_save_network refuses it outright.
        let other = settings("other", "10.153.1.2/24", "managed");
        assert_eq!(registry.save(other), Err(RegistryError::PrivateKeyRequired));
        assert_eq!(registry.networks().len(), 1);
    }

    #[test]
    fn the_reported_settings_leave_out_the_private_key() {
        let (_runtime, registry) = registry();
        let mut office = settings("office", "10.156.0.2/24", "legacy");
        office.private_key = Some(Box::new(zeroize::Zeroizing::new([7; 32])));
        registry.commit(vec![office.clone()]);
        assert!(registry.networks()[0].settings.private_key.is_none());
        assert!(registry.instance("office", &office).is_ok());
    }

    #[test]
    fn a_shut_down_registry_stops_everything() {
        let (_runtime, registry) = registry();
        let office = settings("office", "10.154.0.2/24", "legacy");
        registry.commit(vec![office.clone()]);
        let first = found(&registry, &office);
        registry.shutdown();
        assert!(first.is_retired());
        assert!(registry.networks().is_empty());
        registry.commit(vec![office.clone()]);
        assert!(registry.networks().is_empty());
        assert_eq!(registry.join("office"), Err(RegistryError::Closed));
    }
}
