//! For apps that cannot use the HTTP proxy: local TCP forwards
//! ([`Node::forward_tcp`](super::Node::forward_tcp)) and a TURN server
//! ([`TurnRelay`]) whose relayed traffic goes over the mesh.
//!
//! The TURN relay is how WebRTC media (e.g. LiveKit) reaches an SFU that is
//! only on the mesh, without root or a TUN device: the app is told to use
//! only relay candidates (`iceTransportPolicy: relay`) from the TURN server
//! on 127.0.0.1, and every allocation is a UDP socket on the mesh. Relayed
//! datagrams go only to peers, so the relay cannot reach anything else.

mod forward;
mod turn;

pub use forward::Forward;
pub use turn::{TurnInfo, TurnRelay};
