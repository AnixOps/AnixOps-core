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
}

/// What [`Registry::network`] reports about one network.
#[derive(Clone)]
pub struct NetworkState {
    pub settings: MeshSettings,
    pub joined: bool,
    pub instance: Option<Arc<Instance>>,
    pub failure: Option<Failure>,
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
        for settings in profile {
            // The same network twice in one profile: the first counts, so
            // that the second does not replace it at once.
            if listed.contains(&settings.network_name) {
                continue;
            }
            listed.push(settings.network_name.clone());
            self.put(&mut inner, settings, false);
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
        self.put(&mut inner, settings, true);
        Ok(())
    }

    /// `mesh_join`: starts a network the user left, or one that could not
    /// start before.
    pub fn join(&self, name: &str) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        if inner.closed {
            return Err(RegistryError::Closed);
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
    pub fn set_route_overrides(
        &self,
        name: &str,
        overrides: Vec<IpNet>,
    ) -> Result<(), RegistryError> {
        let mut inner = self.lock();
        let network = inner
            .networks
            .get_mut(name)
            .ok_or(RegistryError::NotFound)?;
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
                instance: network.instance.clone(),
                failure: network.failure,
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
                if same_settings(&network.settings, &settings) {
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
            Some(private) => KeyPair::from_private(**private),
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
        office.private_key = Some(zeroize::Zeroizing::new([7; 32]));
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
