//! The region directory (appendix D.2.2) and the `PUT /v1/mesh` top-level
//! `region` object (D.9.1), and their checks.
//!
//! Errors name a field path and a rule, never a value. A malformed border
//! entry is dropped and counted; anything else wrong refuses the whole
//! directory (D.2.2).

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::backbone::region::RegionId;
use crate::net::IpNet;

/// Most regions in a directory.
pub const MAX_REGIONS: usize = 64;
/// Most border nodes per region.
pub const MAX_BORDERS: usize = 16;
/// Largest directory accepted, in bytes of JSON.
pub const MAX_DIRECTORY_BYTES: usize = 64 * 1024;
/// Longest border display name.
pub const MAX_NAME_LEN: usize = 63;

/// Why a directory or a `region` object was refused: the field path and
/// the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub field: String,
    pub rule: &'static str,
}

impl Invalid {
    fn new(field: impl Into<String>, rule: &'static str) -> Self {
        Self {
            field: field.into(),
            rule,
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.rule)
    }
}

/// One border node to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Border {
    pub name: String,
    pub probe: SocketAddr,
    pub key: [u8; 32],
}

/// One region of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub code: String,
    pub subnet: IpNet,
    /// Valid border nodes only; may be empty when all were dropped.
    pub borders: Vec<Border>,
}

/// A checked directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Directory {
    pub preferred: Option<String>,
    pub regions: Vec<Region>,
    /// Border entries dropped as malformed (`region_probe.rejected`).
    pub rejected: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirectory {
    version: u32,
    #[serde(default)]
    preferred: Option<String>,
    regions: Vec<RawRegion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegion {
    code: String,
    subnet: String,
    borders: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBorder {
    name: String,
    probe: String,
    key: String,
}

/// A display name: 1–63 bytes of lowercase letters, digits or '-', not
/// starting or ending with '-'.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME_LEN
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A probe address: an IP literal and a port, never a host name. Loopback,
/// link-local, multicast, broadcast and unspecified addresses are refused;
/// private ones are allowed (D.2.2).
pub fn probe_address(text: &str) -> Option<SocketAddr> {
    let address: SocketAddr = text.parse().ok()?;
    if address.port() == 0 {
        return None;
    }
    let ok = match address.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            v6.to_ipv4_mapped().is_none()
                && !(v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    };
    ok.then_some(address)
}

/// A responder key: standard base64 with padding, 44 characters, 32 bytes,
/// and not of small order. A small-order point gives an all-zero X25519
/// result with every (clamped, so multiple-of-8) scalar, which would let
/// anyone compute the answers; one exchange with a fixed scalar finds it.
pub fn probe_key(text: &str) -> Option<[u8; 32]> {
    if text.len() != 44 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()?;
    let key: [u8; 32] = bytes.try_into().ok()?;
    let probe = x25519_dalek::StaticSecret::from([0x5a; 32]);
    let shared = probe.diffie_hellman(&x25519_dalek::PublicKey::from(key));
    (!shared.as_bytes().iter().all(|&b| b == 0)).then_some(key)
}

fn border(raw: &Value) -> Option<Border> {
    let raw: RawBorder = serde_json::from_value(raw.clone()).ok()?;
    if !valid_name(&raw.name) {
        return None;
    }
    Some(Border {
        name: raw.name,
        probe: probe_address(&raw.probe)?,
        key: probe_key(&raw.key)?,
    })
}

impl Directory {
    /// Checks a directory given as JSON (D.2.2).
    pub fn from_value(value: &Value) -> Result<Self, Invalid> {
        let size = serde_json::to_vec(value)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size > MAX_DIRECTORY_BYTES {
            return Err(Invalid::new("directory", "at most 64 KiB"));
        }
        let raw: RawDirectory = serde_json::from_value(value.clone()).map_err(|_| {
            Invalid::new("directory", "fields missing, unknown or of the wrong type")
        })?;
        if raw.version != 1 {
            return Err(Invalid::new("directory.version", "must be 1"));
        }
        if raw.regions.len() > MAX_REGIONS {
            return Err(Invalid::new("directory.regions", "at most 64"));
        }
        let mut codes = BTreeSet::new();
        let mut regions: Vec<Region> = Vec::with_capacity(raw.regions.len());
        let mut rejected = 0;
        for (index, region) in raw.regions.into_iter().enumerate() {
            let at = format!("directory.regions[{index}]");
            if RegionId::parse(&region.code).is_none() {
                return Err(Invalid::new(format!("{at}.code"), "must be a region code"));
            }
            if !codes.insert(region.code.clone()) {
                return Err(Invalid::new(format!("{at}.code"), "duplicate"));
            }
            let subnet = IpNet::parse(&region.subnet)
                .filter(|net| net.is_ipv4() && region.subnet.contains('/') && *net == net.trunc())
                .ok_or_else(|| {
                    Invalid::new(
                        format!("{at}.subnet"),
                        "must be an IPv4 CIDR with a zero host part",
                    )
                })?;
            if regions.iter().any(|other| other.subnet.overlaps(&subnet)) {
                return Err(Invalid::new(
                    format!("{at}.subnet"),
                    "overlaps another region",
                ));
            }
            if region.borders.is_empty() || region.borders.len() > MAX_BORDERS {
                return Err(Invalid::new(format!("{at}.borders"), "1 to 16 entries"));
            }
            let mut names = BTreeSet::new();
            let mut borders = Vec::new();
            for raw in &region.borders {
                match border(raw) {
                    Some(b) if names.insert(b.name.clone()) => borders.push(b),
                    _ => rejected += 1,
                }
            }
            regions.push(Region {
                code: region.code,
                subnet,
                borders,
            });
        }
        if let Some(preferred) = &raw.preferred {
            if RegionId::parse(preferred).is_none() {
                return Err(Invalid::new(
                    "directory.preferred",
                    "must be a region code or null",
                ));
            }
        }
        Ok(Self {
            preferred: raw.preferred,
            regions,
            rejected,
        })
    }

    /// Every border node to probe, with its region.
    pub fn borders(&self) -> impl Iterator<Item = (&str, &Border)> {
        self.regions.iter().flat_map(|region| {
            region
                .borders
                .iter()
                .map(move |b| (region.code.as_str(), b))
        })
    }
}

/// Where the current region came from (D.9.1 `basis`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    Latency,
    Credential,
    Admin,
    Migration,
}

impl Basis {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "latency" => Self::Latency,
            "credential" => Self::Credential,
            "admin" => Self::Admin,
            "migration" => Self::Migration,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Credential => "credential",
            Self::Admin => "admin",
            Self::Migration => "migration",
        }
    }
}

/// Most addresses the probe responder listens on (D.9.3).
pub const MAX_RESPONDER_LISTEN: usize = 4;

/// The checked `region` object (D.9.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegionSection {
    pub current: Option<String>,
    pub basis: Option<Basis>,
    pub directory: Option<Directory>,
    /// The probe responder's UDP addresses (D.9.3); `None` without one.
    pub responder: Option<Vec<SocketAddr>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSection {
    current: Option<String>,
    basis: Option<String>,
    #[serde(default)]
    directory: Option<Value>,
    #[serde(default)]
    responder: Option<RawResponder>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponder {
    listen: Vec<String>,
}

/// The responder's listen list: 1–4 distinct IP literals with a non-zero
/// port (any address, the unspecified one included, may be bound).
fn responder_listen(raw: RawResponder) -> Result<Vec<SocketAddr>, Invalid> {
    if raw.listen.is_empty() || raw.listen.len() > MAX_RESPONDER_LISTEN {
        return Err(Invalid::new("region.responder.listen", "1 to 4 addresses"));
    }
    let mut out: Vec<SocketAddr> = Vec::with_capacity(raw.listen.len());
    for (index, text) in raw.listen.iter().enumerate() {
        let at = format!("region.responder.listen[{index}]");
        let address: SocketAddr = text
            .parse()
            .map_err(|_| Invalid::new(at.clone(), "must be an IP literal and a port"))?;
        if address.port() == 0 {
            return Err(Invalid::new(at, "the port must not be 0"));
        }
        if out.contains(&address) {
            return Err(Invalid::new(at, "duplicate"));
        }
        out.push(address);
    }
    Ok(out)
}

impl RegionSection {
    /// Checks the object; `tags` are the `tag`s of the request's networks
    /// (the current region needs `mesh-<current>` among them). `null`
    /// gives `None`.
    pub fn from_value(value: &Value, tags: &[&str]) -> Result<Option<Self>, Invalid> {
        if value.is_null() {
            return Ok(None);
        }
        let raw: RawSection = serde_json::from_value(value.clone())
            .map_err(|_| Invalid::new("region", "fields missing, unknown or of the wrong type"))?;
        let current = match raw.current {
            Some(code) => {
                if RegionId::parse(&code).is_none() {
                    return Err(Invalid::new(
                        "region.current",
                        "must be a region code or null",
                    ));
                }
                let tag = format!("mesh-{code}");
                if !tags.contains(&tag.as_str()) {
                    return Err(Invalid::new(
                        "region.current",
                        "needs a network tagged mesh-<current>",
                    ));
                }
                Some(code)
            }
            None => None,
        };
        let basis = match (raw.basis, &current) {
            (None, _) => None,
            (Some(_), None) => {
                return Err(Invalid::new(
                    "region.basis",
                    "must be null without a current region",
                ))
            }
            (Some(text), Some(_)) => Some(Basis::parse(&text).ok_or_else(|| {
                Invalid::new("region.basis", "latency, credential, admin or migration")
            })?),
        };
        if current.is_some() && basis.is_none() {
            return Err(Invalid::new(
                "region.basis",
                "required with a current region",
            ));
        }
        let directory = match raw.directory {
            None | Some(Value::Null) => None,
            Some(value) => Some(Directory::from_value(&value)?),
        };
        let responder = raw.responder.map(responder_listen).transpose()?;
        Ok(Some(Self {
            current,
            basis,
            directory,
            responder,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";

    fn directory() -> Value {
        json!({
            "version": 1,
            "preferred": "ap",
            "regions": [
                { "code": "eu", "subnet": "10.130.0.0/16", "borders": [
                    { "name": "fra-1", "probe": "198.51.100.7:11013", "key": KEY },
                    { "name": "ams-1", "probe": "[2001:db8::7]:11013", "key": KEY }
                ]},
                { "code": "ap", "subnet": "10.131.0.0/16", "borders": [
                    { "name": "hkg-1", "probe": "10.0.0.7:11013", "key": KEY }
                ]}
            ]
        })
    }

    #[test]
    fn a_good_directory_is_read() {
        let d = Directory::from_value(&directory()).unwrap();
        assert_eq!(d.preferred.as_deref(), Some("ap"));
        assert_eq!(d.regions.len(), 2);
        assert_eq!(d.rejected, 0);
        assert_eq!(d.borders().count(), 3);
        assert_eq!(d.regions[0].borders[1].probe.port(), 11013);
    }

    #[test]
    fn each_rejected_border_kind_is_rejected_alone() {
        for bad in [
            json!({ "name": "x", "probe": "example.com:11013", "key": KEY }),
            json!({ "name": "x", "probe": "[::ffff:192.0.2.1]:11013", "key": KEY }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "7P///////////////////////////////////////38=" }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "7f///////////////////////////////////////38=" }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuAA=" }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw=" }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw" }),
            json!({ "name": "x", "probe": "127.0.0.1:11013", "key": KEY }),
            json!({ "name": "x", "probe": "169.254.1.1:11013", "key": KEY }),
            json!({ "name": "x", "probe": "224.0.0.1:11013", "key": KEY }),
            json!({ "name": "x", "probe": "255.255.255.255:11013", "key": KEY }),
            json!({ "name": "x", "probe": "0.0.0.0:11013", "key": KEY }),
            json!({ "name": "x", "probe": "[fe80::1]:11013", "key": KEY }),
            json!({ "name": "x", "probe": "198.51.100.7:0", "key": KEY }),
            json!({ "name": "x", "probe": "198.51.100.7", "key": KEY }),
            json!({ "name": "-x", "probe": "198.51.100.7:11013", "key": KEY }),
            json!({ "name": "X", "probe": "198.51.100.7:11013", "key": KEY }),
            json!({ "name": "x", "probe": "198.51.100.7:11013", "key": KEY, "extra": 1 }),
            json!("not an object"),
            json!({ "name": "fra-1", "probe": "198.51.100.8:11013", "key": KEY }),
        ] {
            let mut v = directory();
            v["regions"][0]["borders"]
                .as_array_mut()
                .unwrap()
                .push(bad.clone());
            let d = Directory::from_value(&v).unwrap();
            assert_eq!(d.rejected, 1, "{bad}");
            assert_eq!(d.regions[0].borders.len(), 2, "{bad}");
        }
    }

    #[test]
    fn a_region_whose_borders_were_all_dropped_stays_without_borders() {
        let mut v = directory();
        v["regions"][1]["borders"][0]["probe"] = json!("localhost:1");
        let d = Directory::from_value(&v).unwrap();
        assert!(d.regions[1].borders.is_empty());
        assert_eq!(d.rejected, 1);
    }

    /// A change to a valid directory and the field it breaks.
    type Fault = (Box<dyn Fn(&mut Value)>, &'static str);

    #[test]
    fn top_level_faults_refuse_the_whole_directory() {
        let cases: Vec<Fault> = vec![
            (Box::new(|v| v["version"] = json!(2)), "directory.version"),
            (Box::new(|v| v["extra"] = json!(1)), "directory"),
            (
                Box::new(|v| v["preferred"] = json!("A")),
                "directory.preferred",
            ),
            (
                Box::new(|v| v["regions"][1]["code"] = json!("eu")),
                "directory.regions[1].code",
            ),
            (
                Box::new(|v| v["regions"][1]["code"] = json!("e")),
                "directory.regions[1].code",
            ),
            (
                Box::new(|v| v["regions"][1]["subnet"] = json!("10.130.128.0/17")),
                "directory.regions[1].subnet",
            ),
            (
                Box::new(|v| v["regions"][1]["subnet"] = json!("10.131.0.1/16")),
                "directory.regions[1].subnet",
            ),
            (
                Box::new(|v| v["regions"][1]["subnet"] = json!("10.131.0.1")),
                "directory.regions[1].subnet",
            ),
            (
                Box::new(|v| v["regions"][1]["subnet"] = json!("fd00::/64")),
                "directory.regions[1].subnet",
            ),
            (
                Box::new(|v| v["regions"][1]["borders"] = json!([])),
                "directory.regions[1].borders",
            ),
            (
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("regions");
                }),
                "directory",
            ),
        ];
        for (change, field) in cases {
            let mut v = directory();
            change(&mut v);
            assert_eq!(Directory::from_value(&v).unwrap_err().field, field);
        }
        let mut v = directory();
        let one = v["regions"][1].clone();
        let regions = v["regions"].as_array_mut().unwrap();
        regions.clear();
        for i in 0..=MAX_REGIONS {
            let mut r = one.clone();
            r["code"] = json!(format!("r{i}"));
            r["subnet"] = json!(format!("10.{}.0.0/16", i));
            regions.push(r);
        }
        assert_eq!(
            Directory::from_value(&v).unwrap_err().field,
            "directory.regions"
        );
        let empty = json!({ "version": 1, "regions": [] });
        assert!(Directory::from_value(&empty).unwrap().regions.is_empty());
    }

    #[test]
    fn the_region_section() {
        let tags = ["mesh-eu"];
        let section = json!({ "current": "eu", "basis": "latency", "directory": directory() });
        let s = RegionSection::from_value(&section, &tags).unwrap().unwrap();
        assert_eq!(s.current.as_deref(), Some("eu"));
        assert_eq!(s.basis, Some(Basis::Latency));
        assert!(s.directory.is_some());
        assert_eq!(s.responder, None);
        let border = json!({ "current": "eu", "basis": "admin", "directory": null,
            "responder": { "listen": ["0.0.0.0:11013", "[::]:11013"] } });
        let s = RegionSection::from_value(&border, &tags).unwrap().unwrap();
        assert_eq!(s.responder.unwrap().len(), 2);
        assert_eq!(s.directory, None);
        assert_eq!(
            RegionSection::from_value(&Value::Null, &tags).unwrap(),
            None
        );
        let unassigned = json!({ "current": null, "basis": null });
        assert_eq!(
            RegionSection::from_value(&unassigned, &[])
                .unwrap()
                .unwrap(),
            RegionSection::default()
        );
        for (bad, field) in [
            (
                json!({ "current": "ap", "basis": "latency" }),
                "region.current",
            ),
            (json!({ "current": "eu", "basis": "auto" }), "region.basis"),
            (json!({ "current": "eu", "basis": null }), "region.basis"),
            (json!({ "current": null, "basis": "admin" }), "region.basis"),
            (
                json!({ "current": "eu", "basis": "admin", "request": null }),
                "region",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "directory": { "version": 3, "regions": [] } }),
                "directory.version",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "listen": [] } }),
                "region.responder.listen",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "listen": ["a:1", "b:2", "c:3", "d:4", "e:5"] } }),
                "region.responder.listen",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "listen": ["example.com:11013"] } }),
                "region.responder.listen[0]",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "listen": ["0.0.0.0:0"] } }),
                "region.responder.listen[0]",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "listen": ["0.0.0.0:11013", "0.0.0.0:11013"] } }),
                "region.responder.listen[1]",
            ),
            (
                json!({ "current": "eu", "basis": "admin", "responder": { "port": 1 } }),
                "region",
            ),
        ] {
            assert_eq!(
                RegionSection::from_value(&bad, &tags).unwrap_err().field,
                field,
                "{bad}"
            );
        }
    }
}
