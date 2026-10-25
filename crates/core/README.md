# arkitekt-mesh-core

The sans-IO core of [arkitekt-mesh](https://github.com/arkitektio/arkitekt-mesh):
Tailscale's control protocol (Noise, the streamed map), DERP, disco,
WireGuard, NAT traversal paths, the packet filter, tailnet lock and a
netstack (smoltcp), as codecs and state machines that take bytes and time
and give back bytes. `no_std` + `alloc` without the `std` feature (default).

Drivers move the bytes: `arkitekt-mesh` (tokio; embassy and the browser to
come, see `docs/rfc9-sans-io-runtimes.md`). Without std a driver installs
where randomness and the wall clock come from:

```rust
mesh_core::random::set_source(|bytes| hardware_rng_fill(bytes));
mesh_core::time::set_wall_clock(|| unix_time_from_sntp());
```

Monotonic time is always handed in (`mesh_core::time::Instant`,
microseconds since the driver's epoch); with std, `time::now()` gives one.
