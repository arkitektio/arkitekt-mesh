//! A Tailscale-compatible mesh client, written from the protocol up.
//!
//! The core is sans-IO (`arkitekt-mesh-core`, re-exported here at its
//! paths): codecs and state machines that take bytes and time and return
//! bytes, so the same code can run under tokio or on a microcontroller. The
//! `tokio` feature adds the driver that runs a node over real sockets.

pub use mesh_core::{
    control, crypto, derp, disco, filter, keys, nacl, netcheck, netstack, paths, portmap, stun,
    tka, wg,
};

#[cfg(feature = "tokio")]
pub mod driver;
