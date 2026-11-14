//! The Pro switch: a community build reports no Pro features, and a provider
//! registered by an official build answers `pro::status`, `pro::enabled` and
//! the `pro_status` / `set_pro_license` control commands. This file is its own
//! test binary, so the process-wide registration does not leak into the other
//! tests. Everything runs in one test because the steps share that state.

use std::io;
use std::sync::{Arc, Mutex};

use engine_embedded::connections::Dispatcher;
use engine_embedded::control;
use engine_embedded::pro::{
    self, LicenseState, LicenseView, ProBuild, ProFeature, ProProvider, ProStatus,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};

struct Refuse;

impl TcpOutbound for Refuse {
    fn protocol(&self) -> &'static str {
        "test-refuse"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) })
    }
}

/// Accepts the license text "good" and unlocks breakpoints and diff.
#[derive(Default)]
struct StandIn {
    license: Mutex<Option<String>>,
}

impl ProProvider for StandIn {
    fn status(&self) -> ProStatus {
        let license = self.license.lock().unwrap().clone();
        let available = vec![ProFeature::Breakpoints, ProFeature::Diff];
        let (state, view) = match license.as_deref() {
            None => (LicenseState::None, None),
            Some("good") => (
                LicenseState::Valid,
                Some(LicenseView {
                    license_id: "L-1".to_string(),
                    licensee: "dev@example.com".to_string(),
                    updates_until: "2027-11-14".to_string(),
                }),
            ),
            Some(_) => (LicenseState::Invalid, None),
        };
        let enabled = if state == LicenseState::Valid {
            available.clone()
        } else {
            Vec::new()
        };
        ProStatus {
            // The kernel reports `official` whatever the provider says.
            build: ProBuild::Community,
            license: state,
            licensed_to: view,
            available,
            enabled,
        }
    }

    fn set_license(&self, license: Option<&str>) -> ProStatus {
        *self.license.lock().unwrap() = license.map(str::to_string);
        self.status()
    }
}

fn control_json(dispatcher: &Dispatcher, request: &str) -> serde_json::Value {
    serde_json::from_slice(&control::handle(dispatcher, request.as_bytes()).unwrap()).unwrap()
}

#[test]
fn community_build_then_official_provider() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let dispatcher = Dispatcher::single(Arc::new(Refuse));

    // Community build: no provider, nothing enabled, a license is ignored.
    assert_eq!(pro::status(), ProStatus::community());
    assert_eq!(pro::set_license(Some("good")), ProStatus::community());
    for feature in ProFeature::ALL {
        assert!(!pro::enabled(feature), "{}", feature.as_str());
    }
    assert_eq!(
        control_json(&dispatcher, r#"{"cmd":"pro_status"}"#),
        serde_json::json!({
            "build": "community",
            "license": "none",
            "licensed_to": null,
            "available": [],
            "enabled": [],
        })
    );

    // Official build.
    pro::register_pro_provider(Arc::new(StandIn::default()));
    let status = pro::status();
    assert_eq!(status.build, ProBuild::Official);
    assert_eq!(status.license, LicenseState::None);
    assert!(!pro::enabled(ProFeature::Breakpoints));

    let answer = control_json(
        &dispatcher,
        r#"{"cmd":"set_pro_license","license":"not a license"}"#,
    );
    assert_eq!(answer["build"], "official");
    assert_eq!(answer["license"], "invalid");
    assert_eq!(answer["enabled"], serde_json::json!([]));
    // The license text never comes back.
    assert!(!answer.to_string().contains("not a license"));

    let answer = control_json(&dispatcher, r#"{"cmd":"set_pro_license","license":"good"}"#);
    assert_eq!(answer["license"], "valid");
    assert_eq!(answer["licensed_to"]["licensee"], "dev@example.com");
    assert_eq!(
        answer["enabled"],
        serde_json::json!(["breakpoints", "diff"])
    );
    assert!(pro::enabled(ProFeature::Breakpoints));
    assert!(pro::enabled(ProFeature::Diff));
    assert!(!pro::enabled(ProFeature::NetworkConditions));

    let answer = control_json(&dispatcher, r#"{"cmd":"set_pro_license","license":null}"#);
    assert_eq!(answer["license"], "none");
    assert!(!pro::enabled(ProFeature::Breakpoints));
    assert_eq!(
        control_json(&dispatcher, r#"{"cmd":"set_pro_license"}"#)["license"],
        "none"
    );
}

#[test]
fn feature_names_match_serde() {
    for feature in ProFeature::ALL {
        assert_eq!(
            serde_json::to_value(feature).unwrap(),
            serde_json::Value::String(feature.as_str().to_string())
        );
    }
}
