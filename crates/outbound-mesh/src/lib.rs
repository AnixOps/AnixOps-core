//! Intranet mesh networking: a node joins a virtual network of peers and
//! reaches the peers' virtual addresses and the subnets they advertise.
//!
//! The wire protocol is written only from `docs/protocols/intranet-mesh.md`
//! (cited as "spec §n"). The crate registers no outbound yet. See
//! `docs/architecture/mesh-module.md` for the design and its boundaries.
//!
//! - [`config`]: the `"type": "mesh"` settings and their validation.
//! - [`backbone`]: the inter-region backbone of border nodes (spec §17.3),
//!   without I/O.
//! - [`net`]: IPv4/IPv6 networks.
//! - [`scope`]: what counts as intranet. The module never carries traffic to
//!   the public Internet and never acts as an exit.
//! - [`routes`]: the route table filled from peer advertisements, the
//!   destination check before anything is sent, and the source check on
//!   every packet a peer delivers.
//! - [`packet`]: addresses of a raw IP packet, for those checks.
//! - [`region`]: region auto-assignment: the directory, the authenticated
//!   region probe, the measurement and the region change suggestion
//!   (spec §15.8), without I/O.
//! - [`wire`]: framing, the node header and the protobuf subset.
//! - [`legacy`]: the default handshake mode: digest, static keys, payload
//!   encryption and the handshake message.
//! - [`rpc`]: peer RPC packets, pieces, requests and responses.
//! - [`route`]: route synchronisation messages, topology and path choice.
//! - [`secure`]: the secure mode: Noise handshakes, the secret proof,
//!   traffic keys, rotation and the replay window.
//! - [`link`]: one direct connection: the handshake of the network's mode,
//!   then the receive checks and the encryption of packets.
//! - [`driver`] (feature `runtime`): sockets, dialing, listening and timers
//!   around a [`node::Node`].
//! - [`node`]: one node of one network without I/O: connections,
//!   keep-alive, RPC, route synchronisation, forwarding and traffic checks.
//! - [`paths`]: custom paths at run time: capability queries, path states,
//!   probes and the rate limits of a waypoint.
//! - [`waypoint`]: custom paths: path matching, the path state and the
//!   waypoint packet that carries traffic through every waypoint.
//! - [`status`]: what a node agent reads and writes through the kernel's
//!   management API (`/v1/mesh`), and the trait that API drives the mesh
//!   through.

pub mod backbone;
pub mod bridge;
pub mod config;
#[cfg(feature = "runtime")]
pub mod driver;
pub mod legacy;
pub mod link;
pub mod net;
pub mod node;
pub mod packet;
pub mod paths;
pub mod region;
pub mod route;
pub mod routes;
pub mod rpc;
pub mod scope;
pub mod secure;
pub mod status;
pub mod waypoint;
pub mod wire;

pub use config::{
    Cipher, CustomPath, MeshConfig, MeshSettings, PathTarget, PeerEndpoint, Role, RoutePolicy,
    SecurityMode, Transport, CONFIG_VERSION,
};
pub use net::IpNet;
pub use routes::{Denied, PeerId, RouteTable};

/// Config `type` name of a mesh outbound.
pub const TYPE_NAME: &str = "mesh";
