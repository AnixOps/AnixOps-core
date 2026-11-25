//! Intranet mesh networking: a node joins a virtual network of peers and
//! reaches the peers' virtual addresses and the subnets they advertise.
//!
//! The wire protocol (handshake, framing, peer and route exchange) is written
//! only from `docs/protocols/intranet-mesh.md`; until that specification is merged this
//! crate holds the protocol-independent parts and registers no outbound. See
//! `docs/architecture/mesh-module.md` for the design and its boundaries.
//!
//! - [`config`]: the `"type": "mesh"` settings and their validation.
//! - [`net`]: IPv4/IPv6 networks.
//! - [`scope`]: what counts as intranet. The module never carries traffic to
//!   the public Internet and never acts as an exit.
//! - [`routes`]: the route table filled from peer advertisements, the
//!   destination check before anything is sent, and the source check on
//!   every packet a peer delivers.
//! - [`packet`]: addresses of a raw IP packet, for those checks.

pub mod config;
pub mod net;
pub mod packet;
pub mod routes;
pub mod scope;

pub use config::{MeshConfig, MeshSettings, PeerEndpoint, SecurityMode};
pub use net::IpNet;
pub use routes::{Denied, PeerId, RouteTable};

/// Config `type` name of a mesh outbound.
pub const TYPE_NAME: &str = "mesh";
