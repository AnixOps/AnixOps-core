//! Stable ids for nodes read from subscriptions.
//!
//! Clients remember the node a user picked, and the members picked in
//! policy groups, by node id across subscription refreshes. An id therefore
//! has to keep naming the same server when the provider reorders, adds,
//! removes or renames entries. Ids used to be the entry's name made ASCII
//! plus a suffix counted from the entry's position, so `🇭🇰 香港 01` and
//! `🇯🇵 日本 01` both became `clash-ss-01`/`clash-ss-01-2`, and inserting one
//! entry above them silently moved the selection to another country.
//!
//! An id is now derived from what the node connects to, never from its name
//! or position (see `docs/architecture/subscription-node-ids.md`):
//!
//! - **Base:** `{protocol}-{host}-{port}-{endpoint hash}`. The host part is
//!   readable only; the hash (SHA-256, first [`ENDPOINT_HASH_HEX`] hex
//!   digits) covers the protocol, the exact host and port, the transport
//!   ([`ENDPOINT_KEYS`]) and, for a chained node, the endpoint of the node it
//!   connects through.
//! - **Credential suffix:** only when nodes that share a base connect with
//!   different credentials, each gets `-{credential hash}`, a SHA-256 over
//!   the base hash and the credential fields ([`CREDENTIAL_KEYS`]). The
//!   secret never appears in the id, and a node whose base is unique keeps
//!   its id when the provider rotates passwords or UUIDs.
//! - **Duplicate suffix:** entries that are the same node in every respect
//!   get `-2`, `-3`, ... in the order they appear. They are interchangeable,
//!   so which one gets which number does not change where traffic goes.
//!
//! Each node also carries its previous id under
//! [`NODE_METADATA_LEGACY_ID`], so clients can map selections saved by
//! earlier releases to the new ids ([`find_node`]). That lookup is exact
//! only for the same subscription content the old id was assigned from;
//! clients migrate saved ids when they first load the content they already
//! stored, before refreshing it.

use std::collections::{BTreeMap, BTreeSet};

use control_domain::{
    MetadataEntry, NodeDescriptor, Protocol, NODE_METADATA_ANX_PUBLIC_KEY,
    NODE_METADATA_ANX_SERVER_NAME, NODE_METADATA_ANX_USER_KEY,
    NODE_METADATA_HYSTERIA2_OBFS_PASSWORD, NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_IWAN_PASSWORD, NODE_METADATA_IWAN_USERNAME, NODE_METADATA_LEGACY_ID,
    NODE_METADATA_MIERU_PASSWORD, NODE_METADATA_MIERU_TRANSPORT, NODE_METADATA_MIERU_USERNAME,
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SNELL_PSK,
    NODE_METADATA_SNELL_USER_KEY, NODE_METADATA_TLS_SERVER_NAME, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID, NODE_METADATA_V2RAY_TRANSPORT_HOST,
    NODE_METADATA_V2RAY_TRANSPORT_PATH, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME,
    NODE_METADATA_V2RAY_TRANSPORT_TYPE, NODE_METADATA_VIA_UNRESOLVED, NODE_METADATA_VLESS_UUID,
    NODE_METADATA_VMESS_UUID, NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY,
    NODE_METADATA_WIREGUARD_PRE_SHARED_KEY, NODE_METADATA_WIREGUARD_PRIVATE_KEY,
};
use ring::digest;

/// Hex digits of the endpoint hash in an id (40 bits).
pub const ENDPOINT_HASH_HEX: usize = 10;
/// Hex digits of the credential hash in an id (32 bits).
pub const CREDENTIAL_HASH_HEX: usize = 8;
/// Longest readable host part of an id, so ids stay well inside the
/// engine's 128-character outbound id limit with room for client prefixes.
const MAX_HOST_PART_CHARS: usize = 40;
/// Longest protocol part of an id for a protocol without a fixed tag.
const MAX_PROTOCOL_PART_CHARS: usize = 16;
/// Longest `via` chain followed when hashing a chained node's endpoint.
const MAX_VIA_DEPTH: usize = 8;

/// Domain separation of the endpoint hash; changing it changes every id.
const ENDPOINT_HASH_DOMAIN: &str = "anixops.node-id.endpoint.v1";
/// Domain separation of the credential hash; changing it changes ids.
const CREDENTIAL_HASH_DOMAIN: &str = "anixops.node-id.credential.v1";

/// Metadata that tells apart servers behind one host and port (CDN-fronted
/// WebSocket or gRPC nodes, SNI-routed TLS), hashed into the base id.
pub const ENDPOINT_KEYS: &[&str] = &[
    NODE_METADATA_V2RAY_TRANSPORT_TYPE,
    NODE_METADATA_V2RAY_TRANSPORT_HOST,
    NODE_METADATA_V2RAY_TRANSPORT_PATH,
    NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME,
    NODE_METADATA_MIERU_TRANSPORT,
    NODE_METADATA_TLS_SERVER_NAME,
    NODE_METADATA_ANX_SERVER_NAME,
];

/// Credential fields, hashed into the credential suffix only when nodes
/// share a base id.
pub const CREDENTIAL_KEYS: &[&str] = &[
    NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD,
    NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_VLESS_UUID,
    NODE_METADATA_VMESS_UUID,
    NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
    NODE_METADATA_TUIC_UUID,
    NODE_METADATA_TUIC_PASSWORD,
    NODE_METADATA_MIERU_USERNAME,
    NODE_METADATA_MIERU_PASSWORD,
    NODE_METADATA_SNELL_PSK,
    NODE_METADATA_SNELL_USER_KEY,
    NODE_METADATA_IWAN_USERNAME,
    NODE_METADATA_IWAN_PASSWORD,
    NODE_METADATA_ANX_USER_KEY,
    NODE_METADATA_ANX_PUBLIC_KEY,
    NODE_METADATA_WIREGUARD_PRIVATE_KEY,
    NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY,
    NODE_METADATA_WIREGUARD_PRE_SHARED_KEY,
];

/// The id `node` had in releases before stable ids (the entry's name made
/// ASCII plus a position-dependent suffix), if it was read from a
/// subscription format that assigned one.
pub fn legacy_node_id(node: &NodeDescriptor) -> Option<&str> {
    metadata_value(node, NODE_METADATA_LEGACY_ID)
}

/// The node with id `id`, or else the node whose previous id
/// ([`legacy_node_id`]) is `id`, so a selection saved by an earlier release
/// still finds its node. The current id always wins. Callers should save the
/// found node's current id so the old one is not needed again; the old id
/// is only reliable for the subscription content it was assigned from.
pub fn find_node<'a>(nodes: &'a [NodeDescriptor], id: &str) -> Option<&'a NodeDescriptor> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    nodes
        .iter()
        .find(|node| node.id == id)
        .or_else(|| nodes.iter().find(|node| legacy_node_id(node) == Some(id)))
}

/// Replaces the provisional ids the subscription readers gave `nodes` (the
/// previous name-based ids, in subscription order) with stable ids, and
/// records each node's previous id, made unique the way earlier releases
/// did, under [`NODE_METADATA_LEGACY_ID`].
///
/// Runs before `via` names are turned into node ids, since that step reads
/// the final ids. Meant to run once, on the readers' provisional ids; a node
/// that already records a previous id keeps that entry.
pub(crate) fn assign_subscription_node_ids(nodes: &mut [NodeDescriptor]) {
    let legacy = legacy_ids(nodes);
    let endpoints = endpoint_hashes(nodes);
    let bases = nodes
        .iter()
        .zip(&endpoints)
        .map(|(node, endpoint)| base_id(node, endpoint))
        .collect::<Vec<_>>();
    let credentials = nodes
        .iter()
        .zip(&endpoints)
        .map(|(node, endpoint)| credential_hash(node, endpoint))
        .collect::<Vec<_>>();

    // Bases shared by nodes with different credentials need the credential
    // suffix; nodes that differ in nothing share one candidate.
    let mut credentials_by_base: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (base, credential) in bases.iter().zip(&credentials) {
        credentials_by_base
            .entry(base.as_str())
            .or_default()
            .insert(credential.as_str());
    }
    let candidates = bases
        .iter()
        .zip(&credentials)
        .map(|(base, credential)| {
            if credentials_by_base[base.as_str()].len() > 1 {
                format!("{base}-{credential}")
            } else {
                base.clone()
            }
        })
        .collect::<Vec<_>>();

    // Candidates end in a hash of at least eight hex digits, so a counted
    // `-<n>` suffix never equals another candidate; the set still guards it.
    let mut taken: BTreeSet<String> = candidates.iter().cloned().collect();
    let mut occurrences: BTreeMap<&str, usize> = BTreeMap::new();
    let mut ids = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let count = occurrences.entry(candidate.as_str()).or_insert(0);
        *count += 1;
        if *count == 1 {
            ids.push(candidate.clone());
            continue;
        }
        let mut suffix = *count;
        loop {
            let id = format!("{candidate}-{suffix}");
            if taken.insert(id.clone()) {
                ids.push(id);
                break;
            }
            suffix += 1;
        }
    }

    for ((node, id), legacy) in nodes.iter_mut().zip(ids).zip(legacy) {
        // A node that already records its previous id keeps it: its current
        // id is no longer the reader's provisional one, so recomputing would
        // record the stable id instead.
        let legacy = legacy_node_id(node).map(str::to_string).unwrap_or(legacy);
        node.metadata
            .retain(|entry| entry.key != NODE_METADATA_LEGACY_ID);
        node.metadata.push(MetadataEntry {
            key: NODE_METADATA_LEGACY_ID.to_string(),
            value: legacy,
        });
        node.id = id;
    }
}

/// The ids earlier releases gave `nodes`: the reader's name-based id, and
/// when an earlier node took it, `-<n>` with `n` one more than the number of
/// ids taken so far.
fn legacy_ids(nodes: &[NodeDescriptor]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    nodes
        .iter()
        .map(|node| {
            let mut id = node.id.clone();
            if !seen.insert(id.clone()) {
                let mut suffix = seen.len() + 1;
                loop {
                    id = format!("{}-{suffix}", node.id);
                    if seen.insert(id.clone()) {
                        break;
                    }
                    suffix += 1;
                }
            }
            id
        })
        .collect()
}

/// The endpoint hash of every node. A node's `via` (still the name of the
/// node it connects through) is resolved the way the readers resolve it,
/// to the first node of that name, and that node's endpoint hash is hashed
/// in, so renaming the upstream node does not change the chained node's id.
fn endpoint_hashes(nodes: &[NodeDescriptor]) -> Vec<[u8; 32]> {
    let mut by_name = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        by_name.entry(node.name.as_str()).or_insert(index);
    }
    (0..nodes.len())
        .map(|index| endpoint_hash(nodes, &by_name, index, 0))
        .collect()
}

fn endpoint_hash(
    nodes: &[NodeDescriptor],
    by_name: &BTreeMap<&str, usize>,
    index: usize,
    depth: usize,
) -> [u8; 32] {
    let node = &nodes[index];
    let mut context = digest::Context::new(&digest::SHA256);
    hash_field(&mut context, ENDPOINT_HASH_DOMAIN);
    hash_field(&mut context, &protocol_part(&node.protocol));
    hash_field(
        &mut context,
        &node.endpoint.host.trim().to_ascii_lowercase(),
    );
    hash_field(&mut context, &node.endpoint.port.to_string());
    for key in ENDPOINT_KEYS {
        hash_field(&mut context, key);
        hash_field(&mut context, metadata_value(node, key).unwrap_or_default());
    }
    match metadata_value(node, NODE_METADATA_VIA_UNRESOLVED) {
        None => hash_field(&mut context, "direct"),
        Some(via) => match by_name.get(via) {
            Some(&target) if target != index && depth < MAX_VIA_DEPTH => {
                hash_field(&mut context, "via");
                context.update(&endpoint_hash(nodes, by_name, target, depth + 1));
            }
            _ => {
                hash_field(&mut context, "via-name");
                hash_field(&mut context, via);
            }
        },
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(context.finish().as_ref());
    hash
}

/// `{protocol}-{host}-{port}-{endpoint hash}`.
fn base_id(node: &NodeDescriptor, endpoint: &[u8; 32]) -> String {
    let host = truncated(
        super::sanitize_identifier(node.endpoint.host.trim()),
        MAX_HOST_PART_CHARS,
    );
    let host = if host.is_empty() {
        "host".to_string()
    } else {
        host
    };
    format!(
        "{}-{host}-{}-{}",
        protocol_part(&node.protocol),
        node.endpoint.port,
        &lowercase_hex(endpoint)[..ENDPOINT_HASH_HEX]
    )
}

fn credential_hash(node: &NodeDescriptor, endpoint: &[u8; 32]) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    hash_field(&mut context, CREDENTIAL_HASH_DOMAIN);
    context.update(endpoint);
    for key in CREDENTIAL_KEYS {
        hash_field(&mut context, key);
        hash_field(&mut context, metadata_value(node, key).unwrap_or_default());
    }
    lowercase_hex(context.finish().as_ref())[..CREDENTIAL_HASH_HEX].to_string()
}

/// The protocol's part of an id.
fn protocol_part(protocol: &Protocol) -> String {
    let tag = match protocol {
        Protocol::Http => "http",
        Protocol::Socks => "socks",
        Protocol::Shadowsocks => "ss",
        Protocol::Vmess => "vmess",
        Protocol::Vless => "vless",
        Protocol::Trojan => "trojan",
        Protocol::Hysteria => "hysteria",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
        Protocol::WireGuard => "wireguard",
        Protocol::Mieru => "mieru",
        Protocol::Snell => "snell",
        Protocol::Iwan => "iwan",
        Protocol::Anx => "anx",
        Protocol::Other(name) => {
            let tag = truncated(super::sanitize_identifier(name), MAX_PROTOCOL_PART_CHARS);
            return if tag.is_empty() {
                "node".to_string()
            } else {
                tag
            };
        }
    };
    tag.to_string()
}

/// `value` (ASCII) cut to `max` characters, without a trailing `-`.
fn truncated(mut value: String, max: usize) -> String {
    value.truncate(max);
    value.trim_end_matches('-').to_string()
}

/// Hashes `value` with its length first, so field boundaries are
/// unambiguous.
fn hash_field(context: &mut digest::Context, value: &str) {
    context.update(&(value.len() as u64).to_be_bytes());
    context.update(value.as_bytes());
}

fn metadata_value<'a>(node: &'a NodeDescriptor, key: &str) -> Option<&'a str> {
    node.metadata
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.trim())
        .filter(|value| !value.is_empty())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_domain::Endpoint;

    fn shadowsocks(id: &str, name: &str, password: &str) -> NodeDescriptor {
        NodeDescriptor {
            id: id.to_string(),
            name: name.to_string(),
            protocol: Protocol::Shadowsocks,
            endpoint: Endpoint {
                host: "HK.example.test".to_string(),
                port: 8388,
            },
            tags: Vec::new(),
            metadata: vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: "aes-256-gcm".to_string(),
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password.to_string(),
                },
            ],
        }
    }

    /// Pins the id format: clients save these ids, so any change to the
    /// hashing loses every saved selection and needs a migration.
    #[test]
    fn id_format_is_pinned() {
        let mut nodes = vec![shadowsocks("clash-ss-hk", "HK", "hk-secret")];
        assign_subscription_node_ids(&mut nodes);
        assert_eq!(nodes[0].id, "ss-hk-example-test-8388-c89fdfd96c");
        assert_eq!(legacy_node_id(&nodes[0]), Some("clash-ss-hk"));

        let mut nodes = vec![
            shadowsocks("clash-ss-hk", "HK", "hk-secret"),
            shadowsocks("clash-ss-hk", "HK", "hk-other"),
            shadowsocks("clash-ss-hk-copy", "HK copy", "hk-secret"),
        ];
        assign_subscription_node_ids(&mut nodes);
        let ids = nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "ss-hk-example-test-8388-c89fdfd96c-eff56d0e",
                "ss-hk-example-test-8388-c89fdfd96c-e387c107",
                "ss-hk-example-test-8388-c89fdfd96c-eff56d0e-2",
            ]
        );
        let legacy = nodes
            .iter()
            .map(|node| legacy_node_id(node).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(legacy, ["clash-ss-hk", "clash-ss-hk-2", "clash-ss-hk-copy"]);
    }

    #[test]
    fn legacy_suffix_counts_ids_taken_so_far() {
        let mut nodes = vec![
            shadowsocks("a", "a", "1"),
            shadowsocks("b", "b", "2"),
            shadowsocks("c", "c", "3"),
            shadowsocks("b", "b", "4"),
        ];
        assign_subscription_node_ids(&mut nodes);
        let legacy = nodes
            .iter()
            .map(|node| legacy_node_id(node).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(legacy, ["a", "b", "c", "b-4"]);
    }

    #[test]
    fn reassigning_keeps_the_original_legacy_entry() {
        let mut nodes = vec![shadowsocks("clash-ss-hk", "HK", "hk-secret")];
        assign_subscription_node_ids(&mut nodes);
        let id = nodes[0].id.clone();
        assign_subscription_node_ids(&mut nodes);
        assert_eq!(nodes[0].id, id);
        assert_eq!(legacy_node_id(&nodes[0]), Some("clash-ss-hk"));
        assert_eq!(
            nodes[0]
                .metadata
                .iter()
                .filter(|entry| entry.key == NODE_METADATA_LEGACY_ID)
                .count(),
            1
        );
    }
}
