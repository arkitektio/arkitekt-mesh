//! The control plane: Tailscale's ts2021 protocol to the coordination server
//! (Noise over an HTTP upgrade, then HTTP/2), registration and the netmap.

pub mod netmap;
pub mod noise;
pub mod stream;
pub mod types;
