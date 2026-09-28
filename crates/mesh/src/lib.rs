//! A Tailscale-compatible mesh client, written from the protocol up.
//!
//! The core is sans-IO: codecs and state machines that take bytes and time
//! and return bytes, so the same code can run under tokio or on a
//! microcontroller. The `tokio` feature adds the driver that runs a node
//! over real sockets.

pub mod control;
pub mod crypto;
pub mod derp;
pub mod disco;
#[cfg(feature = "tokio")]
pub mod driver;
pub mod filter;
pub mod keys;
pub mod nacl;
pub mod netcheck;
pub mod netstack;
pub mod paths;
pub mod portmap;
pub mod stun;
pub mod tka;
pub mod wg;
