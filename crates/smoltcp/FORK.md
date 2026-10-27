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
  maximum. Off (0) by default. arkitekt-mesh shares an 8 MiB budget among
  a node's sockets, each way.
- `socket::tcp::Socket::set_sack_recovery` (`socket/tcp/sack.rs`): loss
  recovery from the remote's SACKs, RFC 6675 style. Upstream ignores the
  SACKs it gets: a fast retransmit and a timeout both rewind to the
  cumulative ACK and send everything after it again (go-back-N), and its
  congestion window never bounds what is in flight (only what one
  `dispatch` may send). With it on:
  - a scoreboard of SACKed ranges; a recovery begins on the third
    duplicate ACK or once three segments' worth past a hole is SACKed, and
    ends once all sent before it is ACKed;
  - in recovery the holes below the highest SACK are sent again, ahead of
    new data, without moving `remote_last_seq`; after a timeout every hole
    up to what was sent is, and SACKed data is not;
  - the congestion controller hears of one loss a recovery, not of every
    duplicate ACK;
  - the congestion window bounds the pipe (in flight, less SACKed, less
    lost), for new data and holes alike.
  In the simulator at 100 ms with 1 MiB buffers, the share of what was sent
  that was delivered: 45% -> 95% at 1% loss, 13% -> 91% at 5%.
- `socket::tcp::congestion::cubic`: RFC 8312 as written. Upstream computed
  W(t) in octets with C meant for segments (a 1 MiB window took ~90 s to
  regain) and backed off on every duplicate ACK; now in segments, one
  back-off a loss (to 0.7), slow start after a timeout, Reno's W_est where
  it is faster, and RFC 6928's initial window of 10 segments. Two upstream
  tests changed with it (the 100 ms update throttle, ssthresh = cwnd / 2).
- `socket::tcp::Socket::set_tx_buffer_max`: send buffer auto-tuning, as
  Linux's `tcp_sndbuf_expand`: an ACK to a full buffer grows it to twice
  what the path holds (the smaller of the congestion and the remote
  window). Off by default; only safe with SACK recovery, since with
  go-back-N a big flight collapses on loss.
- `storage::RingBuffer::grow`: for the above, owned storage only, keeping
  what is held and what is reassembled past it at the same offsets.
- Tests: `cargo test -p arkitekt-mesh-smoltcp`, and the network simulator
  (throughput against loss, a snapshot) with
  `cargo test -p arkitekt-mesh-smoltcp --release --features _netsim --test netsim`.
- Not with `--all-features`: the `*-count-N` features exclude each other.
