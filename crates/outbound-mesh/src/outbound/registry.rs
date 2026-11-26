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

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use ring::rand::SystemRandom;
use tokio::runtime::Handle;

use super::same_settings;
use super::stack::{Failure, Instance};
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
    local_networks: Option<Vec<IpNet>>,
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
}

impl Registry {
    /// An empty registry whose networks run on `runtime`.
    pub fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            inner: Mutex::new(Inner::default()),
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
            let Inner {
                networks,
                keys,
                local_networks,
                ..
            } = &mut *inner;
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
                    if let Some(instance) = network.instance.take() {
                        instance.retire();
                    }
                } else if network.failure == Some(Failure::InstanceIdChanged) {
                    self.start(keys, local_networks, network);
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
            if let Some(network) = inner.networks.remove(&name) {
                if let Some(instance) = network.instance {
                    instance.retire();
                }
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
            self.start(&mut inner.keys, &inner.local_networks, network);
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
        if let Some(instance) = network.instance.take() {
            instance.retire();
        }
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
        remove(&mut inner, name);
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

    /// The networks of this machine's interfaces, for every network.
    pub fn set_local_networks(&self, networks: Option<Vec<IpNet>>) {
        let mut inner = self.lock();
        for network in inner.networks.values() {
            if let Some(instance) = &network.instance {
                instance.set_local_networks(networks.clone());
            }
        }
        inner.local_networks = networks;
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
            .values()
            .map(|network| NetworkState {
                settings: MeshSettings {
                    private_key: None,
                    ..network.settings.clone()
                },
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
        for (_, network) in std::mem::take(&mut inner.networks) {
            if let Some(instance) = network.instance {
                instance.retire();
            }
        }
        inner.keys.clear();
    }

    /// Adopts `settings` for its network (the later writer wins) and starts
    /// it if it is joined and changed.
    fn put(&self, inner: &mut Inner, settings: MeshSettings, saved: bool) {
        let name = settings.network_name.clone();
        let Inner {
            networks,
            keys,
            local_networks,
            ..
        } = inner;
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
                if let Some(instance) = network.instance.take() {
                    instance.retire();
                }
                // A new key in the settings replaces the one made before.
                if settings.private_key.is_some() {
                    keys.remove(&name);
                }
                network.settings = settings;
                network.failure = None;
                if network.joined {
                    self.start(keys, local_networks, network);
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
                };
                self.start(keys, local_networks, &mut network);
                networks.insert(name, network);
            }
        }
    }

    /// Starts `network` on the engine's runtime with its static key.
    fn start(
        &self,
        keys: &mut BTreeMap<String, KeyPair>,
        local_networks: &Option<Vec<IpNet>>,
        network: &mut Network,
    ) {
        let settings = &network.settings;
        let key = match &settings.private_key {
            Some(private) => KeyPair::from_private(***private),
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
        instance.set_local_networks(local_networks.clone());
        instance.set_route_overrides(network.route_overrides.clone());
        instance.start();
        network.failure = None;
        network.instance = Some(instance);
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

fn remove(inner: &mut Inner, name: &str) {
    if let Some(network) = inner.networks.remove(name) {
        if let Some(instance) = network.instance {
            instance.retire();
        }
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
