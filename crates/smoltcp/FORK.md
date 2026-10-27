# What the fork changes

Forked from smoltcp 0.13.1 (crates.io). Each change is off by default and
meant to go upstream.

- `src/lib.rs`: unused code and clippy's lints are allowed, as for a
  dependency (the workspace's CI denies warnings).
- `socket::tcp::Socket::set_min_rto`: the retransmission timeout's lower
  bound, RFC 6298's 1 s by default (upstream's constant). arkitekt-mesh
  sets 200 ms, Linux's.
- Tests: `cargo test -p arkitekt-mesh-smoltcp`, and the network simulator
  (throughput against loss, a snapshot) with
  `cargo test -p arkitekt-mesh-smoltcp --release --features _netsim --test netsim`.
- Not with `--all-features`: the `*-count-N` features exclude each other.
