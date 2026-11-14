//! Pro edition hooks: the switch the public kernel keeps for the closed
//! Pro debugging modules.
//!
//! The public repository holds no Pro code and no license verifier. Official
//! builds link a closed provider crate (the same overlay pattern as the ANX
//! client build) that calls [`register_pro_provider`] at load time; it owns
//! the Pro modules, the offline license check and the signing public keys.
//! A build without a provider is the community build: [`status`] answers
//! `build: community` and [`enabled`] is `false` for every feature, so the
//! free debugging features work and the Pro ones are simply absent.
//!
//! The client stores the license text itself (Keychain, app data) and hands
//! it over with [`set_license`] when the engine starts or the user imports a
//! license. The same two calls are the runtime control commands
//! `pro_status` and `set_pro_license` ([`crate::control`]).
//!
//! The license text is a credential: it never goes into errors, status or
//! logs. [`ProStatus`] carries only the license id, the licensee label the
//! license names and the end of its update period.

use std::sync::{Arc, RwLock};

use serde::Serialize;

/// The Pro features. Their names are stable: clients and licenses use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProFeature {
    /// Pause a request or response, edit it, then let it go.
    Breakpoints,
    /// Compare two requests or responses side by side.
    Diff,
    /// Network condition presets (latency, bandwidth, loss) per host or app.
    NetworkConditions,
    /// Replay many requests at once, with repeat counts and concurrency.
    BatchReplay,
    /// The debug script API and its editor (existing Loon/Surge plugin
    /// scripts stay free).
    DebugScripts,
}

impl ProFeature {
    /// Every Pro feature, in a stable order.
    pub const ALL: [ProFeature; 5] = [
        ProFeature::Breakpoints,
        ProFeature::Diff,
        ProFeature::NetworkConditions,
        ProFeature::BatchReplay,
        ProFeature::DebugScripts,
    ];

    /// The feature's stable name, as in [`ProStatus`].
    pub fn as_str(self) -> &'static str {
        match self {
            ProFeature::Breakpoints => "breakpoints",
            ProFeature::Diff => "diff",
            ProFeature::NetworkConditions => "network_conditions",
            ProFeature::BatchReplay => "batch_replay",
            ProFeature::DebugScripts => "debug_scripts",
        }
    }
}

/// Which kind of build is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProBuild {
    /// Built from the public sources: no Pro modules.
    Community,
    /// An official build with the Pro modules linked in.
    Official,
}

/// What the provider made of the license it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    /// No license was given.
    None,
    /// Signed by a known key and covers this build.
    Valid,
    /// Malformed, or not signed by a known key.
    Invalid,
    /// Genuine, but this build is newer than the license's update period.
    /// Builds released within the period keep working forever.
    UpdatesExpired,
    /// On the revocation list shipped with this build.
    Revoked,
}

/// The parts of a license the client may show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseView {
    pub license_id: String,
    /// What the license names as its holder (an e-mail address).
    pub licensee: String,
    /// Last day of the update period, `YYYY-MM-DD`.
    pub updates_until: String,
}

/// The answer of [`status`] and the `pro_status` control command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProStatus {
    pub build: ProBuild,
    pub license: LicenseState,
    /// Present when the license is genuine (`valid`, `updates_expired`).
    pub licensed_to: Option<LicenseView>,
    /// Pro features compiled into this build.
    pub available: Vec<ProFeature>,
    /// Pro features usable now: available and unlocked by the license.
    pub enabled: Vec<ProFeature>,
}

impl ProStatus {
    /// The status of a build without a provider.
    pub fn community() -> Self {
        Self {
            build: ProBuild::Community,
            license: LicenseState::None,
            licensed_to: None,
            available: Vec::new(),
            enabled: Vec::new(),
        }
    }
}

/// The closed side of an official build. Implementations check licenses
/// offline and must keep [`ProProvider::status`] cheap: Pro code asks
/// [`enabled`] on its hot paths.
pub trait ProProvider: Send + Sync {
    /// The current status. `build` is reported as `official` whatever the
    /// provider puts there.
    fn status(&self) -> ProStatus;

    /// Replaces the license (`None` removes it) and answers the new status.
    /// A bad license is a [`LicenseState`], not an error.
    fn set_license(&self, license: Option<&str>) -> ProStatus;
}

static PROVIDER: RwLock<Option<Arc<dyn ProProvider>>> = RwLock::new(None);

/// Installs the Pro provider of an official build, replacing an earlier one.
pub fn register_pro_provider(provider: Arc<dyn ProProvider>) {
    *PROVIDER
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(provider);
}

fn provider() -> Option<Arc<dyn ProProvider>> {
    PROVIDER
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn official(mut status: ProStatus) -> ProStatus {
    status.build = ProBuild::Official;
    status
}

/// The Pro status of this build.
pub fn status() -> ProStatus {
    provider().map_or_else(ProStatus::community, |provider| official(provider.status()))
}

/// Hands the stored license to the provider. A community build ignores it.
pub fn set_license(license: Option<&str>) -> ProStatus {
    provider().map_or_else(ProStatus::community, |provider| {
        official(provider.set_license(license))
    })
}

/// Whether `feature` may be used now. Always `false` in a community build.
pub fn enabled(feature: ProFeature) -> bool {
    provider().is_some_and(|provider| provider.status().enabled.contains(&feature))
}
