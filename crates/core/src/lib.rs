//! The sans-IO core of arkitekt-mesh: Tailscale's control protocol, DERP,
//! disco, WireGuard and a netstack, as codecs and state machines that take
//! bytes and time and give back bytes. A driver (`arkitekt-mesh`: tokio,
//! embassy, the browser) moves them over real sockets.
//!
//! no_std + alloc unless `std` (default). Without std a driver installs
//! where randomness and the wall clock come from ([`random::set_source`],
//! [`time::set_wall_clock`]); monotonic time ([`time::Instant`]) is always
//! handed in.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// What std's prelude would bring, for the build without std.
#[allow(unused_imports)]
pub(crate) mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::{format, vec};
}

/// The TCP/IP stack under [`netstack`]: our smoltcp fork (crates/smoltcp)
/// with `fast-tcp`, upstream smoltcp otherwise. The drivers name its types
/// from here, so they always get the one in use.
#[cfg(feature = "fast-tcp")]
pub use mesh_smoltcp as tcpip;
#[cfg(not(feature = "fast-tcp"))]
pub use smoltcp as tcpip;

pub mod control;
pub mod crypto;
pub mod derp;
pub mod disco;
pub mod filter;
pub mod http2;
pub mod keys;
pub mod lock;
pub mod nacl;
pub mod netcheck;
pub mod netstack;
pub mod node;
pub mod paths;
pub mod portmap;
pub mod random;
pub mod stun;
pub mod time;
pub mod tka;
pub mod wg;
