//! The control plane: Tailscale's ts2021 protocol to the coordination server
//! (Noise over an HTTP upgrade, then HTTP/2), registration and the netmap.

#[allow(unused_imports)]
use crate::prelude::*;
pub mod api;
pub mod conn;
pub mod http1;
pub mod netmap;
pub mod noise;
pub mod session;
pub mod stream;
pub mod types;
