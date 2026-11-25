//! Peer RPC (spec §11): route synchronisation and the latency centre run
//! over it. The local management interface of the reference program is not
//! part of the protocol and is not implemented (spec §11.5, requirement R11).

pub mod packet;
pub mod reassembly;

pub use packet::{Descriptor, RpcError, RpcPacket, RpcRequest, RpcResponse};
