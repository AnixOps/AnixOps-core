//! One ANX license per subscription origin (anx spec §2.4.1): a node gets the
//! license of the origin the client stamped on it, never another origin's.
//! Its own test binary: the licenses are process-wide.

use std::collections::BTreeMap;

use control_domain::{
    Endpoint, MetadataEntry, NodeDescriptor, Protocol, NODE_METADATA_ANX_LICENSE_ORIGIN,
    NODE_METADATA_ANX_PUBLIC_KEY, NODE_METADATA_ANX_USER_KEY,
};
use node_import::{outbound_json, set_anx_license, set_anx_licenses, AnxLicense};

fn node(origin: Option<&str>) -> NodeDescriptor {
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_ANX_USER_KEY.into(),
            value: "ab".repeat(32),
        },
        MetadataEntry {
            key: NODE_METADATA_ANX_PUBLIC_KEY.into(),
            value: "aa:bb".into(),
        },
    ];
    if let Some(origin) = origin {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_LICENSE_ORIGIN.into(),
            value: origin.into(),
        });
    }
    NodeDescriptor {
        id: "jp".into(),
        name: "JP ANX".into(),
        protocol: Protocol::Anx,
        endpoint: Endpoint {
            host: "203.0.113.7".into(),
            port: 8443,
        },
        tags: Vec::new(),
        metadata,
    }
}

fn license(key: &str) -> AnxLicense {
    AnxLicense {
        device_key: key.into(),
        device_alg: "ed25519".into(),
        license_cert_path: format!("/licenses/{key}.cert"),
    }
}

#[test]
fn each_node_carries_its_own_origins_license() {
    let a = "https://panel-a.test:443";
    let b = "https://panel-b.test:443";
    set_anx_licenses(BTreeMap::from([
        (a.to_string(), license("aa")),
        (b.to_string(), license("bb")),
    ]));
    // The single license older clients set is never used for a node with an origin.
    set_anx_license(Some(license("shared")));

    let from_a = outbound_json(&node(Some(a))).unwrap();
    assert_eq!(from_a["device_key"], "aa");
    assert_eq!(from_a["license_cert_path"], "/licenses/aa.cert");
    let from_b = outbound_json(&node(Some(b))).unwrap();
    assert_eq!(from_b["device_key"], "bb");
    assert_eq!(from_b["device_alg"], "ed25519");

    // An origin without a license: none at all, not another origin's.
    let other = outbound_json(&node(Some("https://panel-c.test:443"))).unwrap();
    for key in ["device_key", "device_alg", "license_cert_path"] {
        assert!(other.get(key).is_none(), "{key} for an unlicensed origin");
    }

    // A node with no origin (pasted text) keeps the old behaviour.
    assert_eq!(outbound_json(&node(None)).unwrap()["device_key"], "shared");
    set_anx_license(None);
    assert!(outbound_json(&node(None))
        .unwrap()
        .get("device_key")
        .is_none());

    set_anx_licenses(BTreeMap::new());
    assert!(outbound_json(&node(Some(a)))
        .unwrap()
        .get("device_key")
        .is_none());
}
