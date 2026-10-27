# What the fork changes

Forked from smoltcp 0.13.1 (crates.io). Each change is off by default and
meant to go upstream.

- `src/lib.rs`: unused code and clippy's lints are allowed, as for a
  dependency (the workspace's CI denies warnings).
- `socket::tcp::Socket::set_min_rto`: the retransmission timeout's lower
  bound, RFC 6298's 1 s by default (upstream's constant). arkitekt-mesh
  sets 200 ms, Linux's.
- `socket::tcp::Socket::set_rx_buffer_max`: receive buffer auto-tuning,
  as gVisor's `ModerateRecvBuf` and Linux's dynamic right-sizing. The round
  trip is measured from the receiving end (data a whole advertised window
  past an ACK); once a round trip the buffer grows to twice what the
  application read in it, plus 16 segments and a slow-start allowance,
  against an initial 10 segments' worth (Linux's `rcvq_space`). Never past
  the maximum, never shrinking; the window scale is chosen for the
  maximum. Off (0) by default. arkitekt-mesh allows 8 MiB, as tailscale's
  netstack does.
- `storage::RingBuffer::grow`: for the above, owned storage only, keeping
  what is held and what is reassembled past it at the same offsets.
- Tests: `cargo test -p arkitekt-mesh-smoltcp`, and the network simulator
  (throughput against loss, a snapshot) with
  `cargo test -p arkitekt-mesh-smoltcp --release --features _netsim --test netsim`.
- Not with `--all-features`: the `*-count-N` features exclude each other.
