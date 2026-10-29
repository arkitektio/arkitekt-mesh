# CHANGELOG


## v0.10.1 (2026-10-29)

### Bug Fixes

- The first DERP home waits for a netcheck; a dropped region's dial is given up
  ([`e7a15a8`](https://github.com/arkitektio/arkitekt-mesh/commit/e7a15a83c1433245732475e3bc3d6dcd5305d1cb))

A node connected its default home (the lowest region) at start and rehomed a moment later when the
  first netcheck answered, so a board did a full TLS handshake (seconds of its CPU) for a region it
  dropped at once, and the embassy driver did not even stop it: a slot's dial now gives up when the
  slot moves on. With UDP the home waits for the first netcheck answer, at most HOME_WAIT (2 s);
  without UDP (a browser) it connects right away. First contact on the ESP32-S3 after a reset: 12 s
  -> 9 s.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Chores

- The checks' lockfiles at 0.10.0, with the smoltcp fork
  ([`eb54c24`](https://github.com/arkitektio/arkitekt-mesh/commit/eb54c24269b046eb67984dc5764c0e8d771386f9))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>


## v0.10.0 (2026-10-28)

### Bug Fixes

- **embassy**: A DERP region's slot is assigned before its packets go
  ([`2e7d345`](https://github.com/arkitektio/arkitekt-mesh/commit/2e7d345eb70f5cf5517b8917076d2c5d497e7a22))

The driver dispatched a batch of transmits before handling the events the same step raised, so the
  first packets for a region just linked (the peer's home, on first contact) found no slot and were
  dropped (the board's first WireGuard handshake and disco ping to the hub's node). The events go
  first now; the packets wait in the new slot's queue until its connection is up.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Features

- **smoltcp**: Ipv4-clear-dont-frag, IPv4 out without Don't Fragment
  ([`0633151`](https://github.com/arkitektio/arkitekt-mesh/commit/063315145cd998a7af1552e78ae21815002c019d))

smoltcp sets DF on every IPv4 packet but does no path MTU discovery, so on a path with a smaller MTU
  a large packet and all its retransmissions are lost. A board on eduroam (path MTU ~1276) never got
  its 1340-byte WireGuard datagrams through: the agent's REGISTER stalled. With the feature, routers
  fragment them instead.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>


## v0.9.0 (2026-10-27)

### Bug Fixes

- **core**: The replay window forgets the lap before, so late packets get through
  ([`b279f85`](https://github.com/arkitektio/arkitekt-mesh/commit/b279f8560c70176dccc8bff74ed110a8fe3a8f2e))

Arriving in order, a counter never cleared its word of the ring: the clearing started from the word
  of the next counter, not of the highest one (wireguard-go's last >> 6). Once the ring had gone
  round, every packet that came later than a newer one was taken for a replay and dropped, and TCP
  saw a loss where there was only reordering.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **embassy**: Resolve only the tailnet's names
  ([`b0ef613`](https://github.com/arkitektio/arkitekt-mesh/commit/b0ef613d95ec13747df1c2dd1f28848c02273ec2))

Mesh::resolve also tried a name's first label, so "example.com" found a peer named "example": in
  front of all of an app's DNS (RFC-9's routing TcpConnect) it would take other domains' names. It
  now resolves as the tokio node does: bare hostnames and names in the tailnet's domain, to the
  peer's primary address.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **smoltcp**: Reno as RFC 5681 has it
  ([`6c3c0c9`](https://github.com/arkitektio/arkitekt-mesh/commit/6c3c0c9663576cc2d123d6632379289ee31ead86))

Upstream's grew the window a segment every ACK in congestion avoidance (doubling it a round trip),
  never cut it on duplicate ACKs, and halved it on a timeout; harmless while the window bounded
  nothing, not with SACK recovery. Reno with SACK recovery is what a board runs (cubic is f64,
  software floats on an ESP32), and joins the simulator's comparison.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Build System

- The web node on fast-tcp, the fork in release-plz's list
  ([`6fe8d94`](https://github.com/arkitektio/arkitekt-mesh/commit/6fe8d94da53c073d6a413eb786fb92570b67aff7))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Code Style

- **embassy**: The node task without an expect after a check
  ([`ab6d5a8`](https://github.com/arkitektio/arkitekt-mesh/commit/ab6d5a8bc458582721f1e78d30801375f4c5f567))

clippy's unnecessary_unwrap (Rust 1.93) failed the embassy and web jobs.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Documentation

- **rfc9**: Phases 7b and 7c
  ([`a00f336`](https://github.com/arkitektio/arkitekt-mesh/commit/a00f33667945e6b1abbb8bd6bac3598f6d6704a6))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Features

- **core**: A fast-tcp mode on our own smoltcp fork
  ([`4ee0171`](https://github.com/arkitektio/arkitekt-mesh/commit/4ee01719280944190f67b35c494a6ca763c52ef2))

crates/smoltcp is smoltcp 0.13.1, published as arkitekt-mesh-smoltcp and unchanged so far (lints
  aside): the place for faster loss recovery than upstream's. mesh-core's `fast-tcp` takes it as the
  TCP/IP stack; without it upstream smoltcp, as a board has (shared with embassy-net, so no second
  copy in flash). arkitekt-mesh turns it on by default.

mesh_core::tcpip is the stack in use, so the drivers name its types from there and no longer depend
  on smoltcp themselves.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Fast-tcp grows a receive buffer to what its application reads
  ([`6328107`](https://github.com/arkitektio/arkitekt-mesh/commit/632810741447b8e888d7d373663ef99e50537b5e))

The fork tunes a socket's receive buffer as gVisor and Linux do (once a round trip, twice what the
  application read in it, up to a maximum, never shrinking; Socket::set_rx_buffer_max).
  Limits::tcp_buffer_max (8 MiB, tailscale's; 0 for small()) is that maximum: a connection starts at
  tcp_buffer and its window follows the reader, so one stream is no longer capped at 1 MiB a round
  trip.

Lab, direct download, one stream: 25 -> 78-89 MiB/s at 20 ms, 8.5 -> 20 at 100 ms (tsnet, same lab:
  93, 22).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Fast-tcp repairs losses from SACKs, so send buffers grow too
  ([`b64b001`](https://github.com/arkitektio/arkitekt-mesh/commit/b64b001bfb5c11dab0f6f2a41634af20ba2d6789))

The fork gains SACK loss recovery (Socket::set_sack_recovery, RFC 6675 style): a scoreboard of what
  the peer SACKed, the holes sent again instead of everything after the first (go-back-N), one
  congestion event a loss instead of one a duplicate ACK, and the congestion window bounding what is
  in flight, which upstream's never did. Its cubic is RFC 8312 in segments: upstream's worked in
  octets and took ~90 s to regain a 1 MiB window.

With it, fast-tcp's send buffers grow as the receive buffers do, from a shared 8 MiB budget
  (Limits::tcp_send_buffer_max).

Simulator, 100 ms, 1 MiB buffers, delivered/sent: 45% -> 95% at 1% loss. Lab, direct upload: one
  stream 41 -> 103 MiB/s at 20 ms, 8.8 -> 23 at 100 ms; 8 streams at 20 ms 206 (9 with send growth
  but no SACK).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Fast-tcp retransmits after 200 ms and holds 32 out-of-order ranges
  ([`4b3f686`](https://github.com/arkitektio/arkitekt-mesh/commit/4b3f686d33679569bb459ea2edf2e3f29c779762))

The fork gains Socket::set_min_rto (RFC 6298's 1 s stays the default); fast-tcp sets Linux's 200 ms,
  and smoltcp's assembler holds 32 ranges instead of 4, so a receiver with more holes keeps what
  arrives.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Fast-tcp's receive buffers grow from one budget; send growth, off
  ([`fe7ccf1`](https://github.com/arkitektio/arkitekt-mesh/commit/fe7ccf1b442c3626d686c1a597333676819ce340))

The receive buffers now grow from Limits::tcp_buffer_max for all of them, not each: what their
  windows let the peers send arrives through one UDP socket and one loop, and 8 streams of 8 MiB
  each overran it (10,000 dropped datagrams a run in the lab). One stream may still take all of it.

The fork also grows a transmit buffer (Socket::set_tx_buffer_max, as Linux's tcp_sndbuf_expand),
  behind Limits::tcp_send_buffer_max, which stays 0: with megabytes in flight and go-back-N
  retransmits, one loss resends them all (8 uploads at 20 ms in the lab: 230 -> 9 MiB/s), until
  retransmits are selective.

CI also tests mesh-core alone, on upstream smoltcp.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **embassy**: Mesh::restart, the same node started over
  ([`412493c`](https://github.com/arkitektio/arkitekt-mesh/commit/412493c000af2b550a3736e7f819f7a7837955cb))

After control refused a node or could not be reached before it joined, run() ends; a board then made
  a new Mesh for every attempt, leaking one each time. Mesh::restart(config) starts the same node
  over in place (the config is a RefCell now, borrowed briefly). checks/embassy `--restart` (in CI):
  refused with a wrong key, restarted with the right one, then the usual scenario.

tests/lab.rs: a node ionskale knows rejoins without its key and with its key expired (a board's
  later boots), as ionskale's registration takes a known machine and node key whatever the auth key.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **smoltcp**: Smoltcp's name for the fork, for a firmware's patch
  ([`54edbd9`](https://github.com/arkitektio/arkitekt-mesh/commit/54edbd969f409d08ffda7cec462135c24d858d79))

crates/smoltcp-patch is a package named smoltcp 0.13.1 (unpublished, outside the workspace) that
  re-exports the fork with every feature, so a firmware's [patch.crates-io] puts embassy-net on it
  too: one TCP/IP stack with SACK recovery, not upstream's plus ours. ESP32-S3 with the mesh: +5.5
  KB of flash over upstream, against +40 KB for both stacks.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Testing

- **embassy**: The board's TLS under the driver (RFC-9 phase 7a)
  ([`a3bfc24`](https://github.com/arkitektio/arkitekt-mesh/commit/a3bfc24cdf804beeb99cf65a1ab5a5b70bb1a559))

checks/embassy `--board-tls` dials control and DERP through arkitekt-embassy's conn::open (the
  firmware's TLS) over the host's TCP, with arkitekt-embassy's runtime for its clock;
  MESH_CHECK_ECHO_KIB sets the echo's size. It found that embedded-tls (arkirust 0.16) loses a
  record header when a read is cancelled: a 256 KiB echo over DERP stalled every time, where rustls
  passed in 3 s. arkitekt-embassy's TLS is now rustls's unbuffered client (arkirust, unreleased): 1
  MiB in 4.4 s through it. RFC-9 records it; the CI step follows arkirust's release.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **lab**: The peer on one CPU, and netem's queue out of the way
  ([`a4e6df8`](https://github.com/arkitektio/arkitekt-mesh/commit/a4e6df8692f7d04fcdbaceafa0ce70a87c7d0fc4))

Spread over several CPUs, the packets netem held back overtook each other in blocks of up to 64,
  which cost a smoltcp receiver 3x at 20 ms; and netem's 1000-packet queue capped our datagrams (but
  not tsnet's GSO batches) at ~12 MiB/s at 100 ms, which stalled 8-stream uploads.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **lab**: The relay's queue depth as a knob, the peer's tailscale counters
  ([`5b8c5dd`](https://github.com/arkitektio/arkitekt-mesh/commit/5b8c5dd6eeefebd4c66371a80e8cc551357ba86e))

MESH_LAB_DERP_QUEUE sets ionskale's per-receiver DERP queue
  (TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH); the peer serves tailscale's clientmetrics at
  /debug/metrics (e.g. its DERP sends dropped).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>


## v0.8.0 (2026-10-25)

### Bug Fixes

- **embassy**: Connect timeouts, DERP slot eviction, a lock store, direct paths checked
  ([`5a49d22`](https://github.com/arkitektio/arkitekt-mesh/commit/5a49d22fec0079427b991a7a16383d18717c76b5))

- Control's connection (dial, TLS, GET /key) gives up after 30 s, as a failed connect; a DERP node's
  dial and handshake after 10 s (then the region's next node), as on tokio. A hanging handshake
  stalled control. - A region asked for with every slot taken evicts the one not home (its region
  closed for the core) or, with none to give, is closed again: the core had counted it linked and
  dropped its packets until the netmap changed. - Config::lock_store keeps the verified tailnet-lock
  chain across starts. - Mesh::direct_path. The check now asserts a direct path comes up unless
  DERP-only, and CI runs the harness's two DERP regions too (both slots, rehoming).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Chores

- Split arkitekt-mesh out of arkirust
  ([`d04d7ef`](https://github.com/arkitektio/arkitekt-mesh/commit/d04d7ef401ac0b29d79edca7207070882ae31278))

The mesh client, meshd and the Python bindings now live in their own repository, with their history
  from arkirust. Own workspace, CI and lockstep release (continuing at 0.7.0); the URLs point here.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Documentation

- Rfc-9, a sans-IO node driven by tokio, embassy and the browser
  ([`1cc7149`](https://github.com/arkitektio/arkitekt-mesh/commit/1cc71497f8d31478185d61d4b1907ec538ff1198))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- The ESP32 firmware is esp32-mesh-demo
  ([`afbc06f`](https://github.com/arkitektio/arkitekt-mesh/commit/afbc06fb534667d11beec07521fe7fb35dcc673b))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **meshd**: There are no meshd wheels; binaries are on the releases
  ([`7d9b1a1`](https://github.com/arkitektio/arkitekt-mesh/commit/7d9b1a1b72eff902e4d5e130e3fb9551c6a73e39))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **rfc9**: Accepted: a core crate, h2 on tokio, HTTP/1.1 over Noise elsewhere with ionskale, the
  web driver
  ([`7292bb2`](https://github.com/arkitektio/arkitekt-mesh/commit/7292bb2caf35f036fb990d8a9e468a13c7de4f43))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **rfc9**: Http/2 everywhere: h2 on tokio, our own sans-IO client without std
  ([`8561319`](https://github.com/arkitektio/arkitekt-mesh/commit/8561319ed5bafe0c489ae99d2dd5ff7bb0a26a55))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Features

- Arkitekt-mesh-core, the sans-IO core without std (RFC-9 phase 1)
  ([`b110acc`](https://github.com/arkitektio/arkitekt-mesh/commit/b110accf2f0b22500fce9b0bb8bd37e2d01bfd7f))

The codecs and state machines (control, crypto, DERP, disco, the filter, keys, netcheck, the
  netstack, paths, port mapping, STUN, tailnet lock, WireGuard) move to arkitekt-mesh-core, no_std +
  alloc without its `std` feature (default). arkitekt-mesh re-exports them at their old paths.

Time is mesh_core::time::Instant (microseconds since the driver's epoch), handed in as before; the
  wall clock (WireGuard's TAI64N timestamps) and randomness are hooks a driver without std installs
  (time::set_wall_clock, random::set_source), the OS's with std. HashMaps are hashbrown's.

The core builds for thumbv7em-none-eabihf, wasm32-unknown-unknown and xtensa-esp32s3-none-elf (a
  no-std CI job); every test passes unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: An HTTP/2 client and HPACK without I/O (RFC-9 phase 3)
  ([`bf57bc4`](https://github.com/arkitektio/arkitekt-mesh/commit/bf57bc421b6ed3f9c421be8f3d5d308ca94870b2))

mesh_core::http2::Connection, for the drivers without std (tokio keeps the h2 crate): the preface
  and SETTINGS, HEADERS + CONTINUATION, DATA with padding, flow control both ways (receive windows
  handed back only as the app releases what it consumed, request bodies held for the server's
  windows), PING, GOAWAY, RST_STREAM; client streams only, no push, priorities ignored. Input in any
  slicing: a frame may span many Noise records.

HPACK decodes in full (dynamic table, size updates, every literal form, Huffman, checked padding and
  EOS) and encodes statelessly (static table and plain literals).

Tests: RFC 7541's examples, frame-level error cases, and a conversation

with the h2 crate's server fed in 1000-byte slices: 20 requests through the dynamic table, a 1 MiB
  response through a 64 KiB window, the server held at the window when nothing is released, a 300 KB
  request body through 16 KiB windows, a 40 KB header in CONTINUATIONs, RST_STREAM, PING, and GOAWAY
  with a stream still finishing.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Controlconn over a WebSocket, both forms against ionskale (RFC-9 phase 3)
  ([`9f9517b`](https://github.com/arkitektio/arkitekt-mesh/commit/9f9517bbc0e118e5d15932350694abd4426b5354))

ControlConn::upgraded is the connection whose upgrade the driver makes: the WebSocket form, GET
  /ts2021 with the tailscale-control-protocol subprotocol and the Noise initiation in the query
  (api::websocket_path, its base64 percent-encoded: Go's form parsing would read '+' as a space), as
  a browser's WebSocket makes it. The stream then starts at the handshake response.

tests/lab_control_conn.rs runs ControlConn against the mesh lab's ionskale over TLS, by the HTTP
  upgrade and by WebSocket: register with the lab key, the first netmap with the lab peer. The
  WebSocket form needed ionskale fixed (it routed only POST /ts2021, and lost WebSocket connections
  served under net/http); RFC-9 records it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Controlsession, the control loop's policy without I/O (RFC-9 phase 5a)
  ([`c66761b`](https://github.com/arkitektio/arkitekt-mesh/commit/c66761bc9078f78772b2d80a1e2436f7ac6d66cd))

mesh_core::control::session::ControlSession decides what the tokio driver's start-up, map_loop and
  update_loop did: connect, register (a refusal before the first registration ends it: Refused,
  KeyExpired, NeedsLogin with or without a URL; after it, retried), open the stream with the current
  tailnet-lock head, the 120 s quiet limit, reconnect waits of 1 s doubling to 30 s (back to 1 s on
  any response, 100 ms after a rebind), keepalives kept to itself, and updates of our endpoints,
  home and lock head coalesced, one in flight, one after every (re)connect. Calls go out by the
  session's own ids; the driver makes them over its transport and reports answers, connections and
  drops back.

On tokio, ControlLink makes them with the h2 crate's client (calls as tasks, answers on a bounded
  channel, a dropped connection's ignored), and one control_loop replaces map_loop and update_loop.
  Every test passes unchanged, the lab's restart and tailnet-lock suites included; the session's
  rules have pure tests of their own.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Derpconn, a DERP connection without I/O (RFC-9 phase 4)
  ([`37d3476`](https://github.com/arkitektio/arkitekt-mesh/commit/37d3476965f9c899ce78e831b6e8a53cdc8fbac9))

mesh_core::derp::conn::DerpConn: the HTTP upgrade (or none, after a driver's WebSocket upgrade with
  the "derp" subprotocol), the server key, client and server info, the preferred note, pings
  answered, the 120 s quiet limit as a deadline, a restarting server as an end; the server's frames
  as events. Backoff holds the reconnect delays (reset once a connection came up).

The tokio DERP task is the bytes around it: dialing a region's nodes, TLS, the reads (16 KiB: with 4
  KiB reads 8-stream DERP download lost about a fifth), the paced writes. tests/lab_derp_conn.rs
  relays between an HTTP-upgrade client and a WebSocket client through the lab's ionskale.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Locksync, tailnet-lock sync without I/O (RFC-9 phase 5b)
  ([`1b7aa89`](https://github.com/arkitektio/arkitekt-mesh/commit/1b7aa89058f3ec5d707dd4824e18a63d0f36dd55))

mesh_core::lock::sync::LockSync takes the driver's sync apart into its calls: the genesis on the
  first announcement, a disablement only when its secret verifies, offer and verified updates when
  the heads differ, then sync/send (not served everywhere: logged, not an error). One Call at a
  time, answered by the driver; it ends in the lock to install, failed closed (unverified: every
  peer hidden) when there is no authority to keep. The tokio driver's sync is now a loop around it;
  the tailnet-lock suites (tka, lock, lab_lock) pass unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: Nodecore, the node's state and policy without I/O (RFC-9 phase 2)
  ([`10e3b5e`](https://github.com/arkitektio/arkitekt-mesh/commit/10e3b5e52bdb32503dd92326bf372b1ff2e29559))

mesh_core::node::NodeCore holds what the tokio loop held and decided: the tunnel, paths, netstack,
  netmap, packet filter and tailnet lock, and when to probe STUN, report endpoints, re-home by
  latency, connect or drop a DERP region, hold the sockets back for a full DERP queue, and what a
  rebind resets. Datagrams, DERP packets, map responses and rebinds go in; transmits, events
  (ConnectDerp, DropDerp, Endpoints, Home) and the next deadline come out. Tailnet lock's state
  moves to mesh_core::lock; syncing it with control stays in the driver.

The tokio driver is the loop around it: sockets, the DERP tasks and their queues (the core is told
  the fullest one's room), the map and update tasks. Every test passes unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **core**: The control protocol without I/O, and ControlConn on our HTTP/2 (RFC-9 phase 3)
  ([`0c74676`](https://github.com/arkitektio/arkitekt-mesh/commit/0c746762dcefd7d723590d9c06f02d0270c68d30))

What any transport needs, in mesh_core::control: - http1: request heads, response heads (the bytes
  after them kept), small bodies (chunked, Content-Length): GET /key, the ts2021 upgrade, DERP's. -
  noise::NoiseStream: the record layer as a byte stream in any slicing, the server's early payload
  dropped. - api: Call (register, map, Go-style RPC) with its headers, the answers parsed from
  status and body, MapFrames reading a map stream's frames as they arrive (each through MapReader,
  never whole). - conn::ControlConn: upgrade, Noise and Calls over our HTTP/2 on one byte stream,
  for the drivers without std; map responses as events, windows handed back as they are consumed.

The tokio driver keeps the h2 crate and now goes through http1, NoiseStream, Call and MapFrames, so
  the whole suite runs them. ControlConn runs against tailscale's test control server (Go's HPACK
  encoder, its long map stream) in tests/control_conn.rs: register, the update, the streamed netmap
  with the peer, a call beside the open stream, and a handshake to the wrong key.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **embassy**: Arkitekt-mesh-embassy, the node without std (RFC-9 phase 5c)
  ([`72e4b9e`](https://github.com/arkitektio/arkitekt-mesh/commit/72e4b9e270be3d39efb02af9b0c026f937e597fb))

A new crate (lib mesh_embassy, no_std + alloc, no Send, no executor of its own): Mesh::run is one
  future with the control task (ControlSession, ControlConn after GET /key, LockSync before a map
  response applies), two DERP slots (DerpConn, Backoff) and the node loop (NodeCore over the app's
  UDP, its timers), over what the app gives: Udp (one IPv4 socket) and Dial (streams to host:port,
  TLS or plain). The app gets TCP over the tunnel: Mesh::connect, and embedded-nal-async TcpConnect
  and Dns from the netmap's names. Config::small fits RFC-9's board budget (16 KiB TCP buffers and
  HTTP/2 windows).

checks/embassy runs it on the host (embassy's std executor, async-io, futures-rustls): it joins
  tailscale's test control and reaches the peer over the tunnel (HTTP, a 64 KiB echo), with direct
  paths and DERP only; the new CI job `embassy` runs both and gates the release. Against the lab's
  ionskale (TLS, DERP certificates checked) by hand. Builds for xtensa-esp32s3-none-elf.

The workspace's mesh-core is without std by default now; the std crates ask for it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **web**: Arkitekt-mesh-web, the node in the browser (RFC-9 phase 6)
  ([`e95f5b0`](https://github.com/arkitektio/arkitekt-mesh/commit/e95f5b0bd08df2b85f915d5fb1c71aeb6ffcbad6))

The embassy driver learns WebSockets: a Dial with WEBSOCKET set gives WebSocket streams (each write
  one binary message) and a GET, and the driver then fetches control's /key, upgrades by GET /ts2021
  (ControlConn::upgraded) and reaches DERP by GET /derp (DerpConn::upgraded). Dials without it are
  unchanged.

arkitekt-mesh-web (wasm32 only; empty elsewhere) is that driver on the JS event loop: WsConn over
  the JS WebSocket (cancel-safe reads), fetch for /key, no UDP (DERP only), randomness and the wall
  clock from crypto.getRandomValues and Date.now, and a time driver of its own on performance.now
  and setTimeout (embassy-time's wasm driver needs a window: no node, no workers). start() runs the
  node, Mesh connects TCP.

checks/web runs it under node (wasm-pack): it joins tailscale's test control by WebSocket and gets
  the peer's page over DERP by WebSocket; ./run.sh lab does the same against the lab's ionskale. The
  new CI job `web` runs the harness and gates the release.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Performance Improvements

- **mesh**: Act on the core's events under the lock the loop holds
  ([`575c7a7`](https://github.com/arkitektio/arkitekt-mesh/commit/575c7a79f1faf2c50dd2cf2b42fcb9b6bb80eba0))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

### Testing

- **mesh**: The harness helper is only shared with meshd now
  ([`23cebbc`](https://github.com/arkitektio/arkitekt-mesh/commit/23cebbcb46e673afc4e37f0ee40d8c2e9926aa67))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- **mesh-lab**: Run lovekit's lab test from the arkirust checkout
  ([`d2e7718`](https://github.com/arkitektio/arkitekt-mesh/commit/d2e77184364ab925b5e811254637f8c53ee98176))

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>


## v0.7.0 (2026-10-23)


## v0.6.0 (2026-10-23)


## v0.5.1 (2026-10-20)

### Bug Fixes

- Publish the state-requirements release
  ([`360ee3c`](https://github.com/arkitektio/arkitekt-mesh/commit/360ee3c106a70482b53d594d0c12a2733ab3f06a))

The release run of 0.5.0 had its tag push rejected and published nothing; this cuts the release from
  it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>


## v0.5.0 (2026-10-20)


## v0.4.0 (2026-10-20)


## v0.3.1 (2026-10-07)

### Bug Fixes

- Attach the arkitekt-meshd binaries to every release
  ([`6bd33b0`](https://github.com/arkitektio/arkitekt-mesh/commit/6bd33b0edb60c8ee760a15f098a78520cff460aa))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_01GwdBkEZRCRUEgLvWV2pvDL

### Continuous Integration

- **release**: Semantic-release decides the version, and a release publishes everything
  ([`4fce136`](https://github.com/arkitektio/arkitekt-mesh/commit/4fce1369f3daf9d31385f8ecbe48372a024a84c5))

The release PR never worked here, so versions were bumped by hand. A push to main is now the
  release: once CI is green, semantic-release bumps the workspace version from the commits, tags and
  creates the GitHub release, release-plz publishes the crates, and release.yaml (PyPI) and
  meshd.yml (binaries, onto the same GitHub release) are started on the tag.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_01GwdBkEZRCRUEgLvWV2pvDL


## v0.3.0 (2026-10-07)

### Chores

- Release v0.3.0
  ([`3ca07fa`](https://github.com/arkitektio/arkitekt-mesh/commit/3ca07fa7f09f27bc50de4d0834922f5c91ac8bd8))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

- Stop tracking Python bytecode
  ([`b167874`](https://github.com/arkitektio/arkitekt-mesh/commit/b167874ac45d0b7beb400294686c5d6db058a169))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

### Continuous Integration

- **release**: Publish arkitekt-mesh to PyPI with every release
  ([`55087d0`](https://github.com/arkitektio/arkitekt-mesh/commit/55087d089b9c06fedc467b4f7c45874a30c8a8ba))

release-plz.yml starts release.yaml on the release's vX.Y.Z tag once the crates are published: the
  tag itself starts nothing, as it is pushed with GITHUB_TOKEN. release.yaml publishes on any tag
  that carries the workspace version, and on a branch stays a dry run.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

### Features

- **mesh**: Throughput and first-connection fixes, with a bench to measure them
  ([`e8977f6`](https://github.com/arkitektio/arkitekt-mesh/commit/e8977f6b75dc643bce9a0d6745c830f6049a01a8))

Five causes, each measured with the new tests/bench.rs (docs/rfc7, "Results"):

- A connection had 64 KiB in flight per round trip. Limits::tcp_buffer is 1 MiB now, settable as
  --tcp-buffer on meshd, tcp_buffer= in the Python bindings and MeshOptions.tcp_buffer. - Downloads
  overflowed the kernel's UDP receive buffer: udp_buffer is 4 MiB and the node receives 64 datagrams
  per batch. - DERP uploads stalled on silent local queue drops and the relay's 32-packet client
  queue: the netstack is back-pressured and data frames are paced (derp_burst); Node::derp_dropped
  counts what was lost. - The first connection took 5 to 10 s, because a WireGuard initiation was
  only retried after 5 s: it is retried early (250 ms, 500 ms, 1 s, ...), and a session binds its
  last UDP port again after a restart. - The proxy dialed once per http:// request: it keeps a
  pooled client per host.

The mesh lab's peer can shape its link (lab.sh netem), which is what shows a window-limited
  connection at all.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>


## v0.2.0 (2026-09-30)

### Continuous Integration

- Mesh workflow on Linux, macOS and Windows; clang for livekit
  ([`51dc966`](https://github.com/arkitektio/arkitekt-mesh/commit/51dc966a504faed03f21910b44819615d6f9dc1b))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- **meshd**: Define __ARM_ARCH for ring in aarch64 manylinux wheels
  ([`2e212be`](https://github.com/arkitektio/arkitekt-mesh/commit/2e212be9125555d9e791aed172f172bb1134e5b9))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- **meshd**: Sign and notarize macOS binaries, smoke-test, manual runs
  ([`e469af2`](https://github.com/arkitektio/arkitekt-mesh/commit/e469af2d1d8cd962e5749f177b6f6888767bb8a3))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- **release**: Publish arkitekt-mesh to PyPI from release.yaml
  ([`79bf59e`](https://github.com/arkitektio/arkitekt-mesh/commit/79bf59ec77a40a43c6284819a08eb1acba250476))

Only the in-process bindings go to PyPI: Python fakts runs the node with arkitekt-mesh, so the
  arkitekt-meshd wheels (crates/meshd/python) are gone; the binary stays on the GitHub release
  (meshd.yml).

release.yaml, on a mesh-vX.Y.Z tag: tests, abi3 wheels for Linux (glibc, musl), macOS universal2 and
  Windows (x64, arm64), plus an sdist, each with LICENSE and LICENSE-THIRD-PARTY; every wheel
  installed and run on its platform (architecture asserted) and the sdist checked and built from
  source, before trusted publishing without an environment.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

### Documentation

- Mesh RFCs, ESP32 notes, README
  ([`28b86d3`](https://github.com/arkitektio/arkitekt-mesh/commit/28b86d358b2c13db654fd27af4d238b0ff461b01))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- Rfc-6 status after the first cross-platform CI runs
  ([`cecdaa5`](https://github.com/arkitektio/arkitekt-mesh/commit/cecdaa54fd170bbdc9c7421f8d44fc4768408590))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

### Features

- Rekuest-protocol: every agent-protocol frame, for agents and servers
  ([`347a10c`](https://github.com/arkitektio/arkitekt-mesh/commit/347a10c79bf688df8584ff649cc851875c1420d0))

The wire types move out of rekuest into their own crate, and grow to the whole protocol the Python
  server speaks: the agent's requests (probe, state revision, cancel/interrupt/ pause/resume), every
  reply, the 19 execution-event mirrors, a workflow's resume journal, paused details, and the
  RECORD/HOLD effects. FromAgent and Envelope are generic over what REGISTER declares (the agent's
  own AgentDeclaration by default). The contract is the server-generated fixture with every field of
  every frame set; all 66 round-trip.

UNLOCK's task and SHELVE/UNSHELVE's ref are optional, as in Python. The workspace moves to 0.2.0 in
  lockstep, so the arkitekt that has Alias is published before arkitekt-mikro.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

- **mesh**: Our own Tailscale-compatible client (arkitekt-mesh)
  ([`c5bb870`](https://github.com/arkitektio/arkitekt-mesh/commit/c5bb870c80bf6fdc3a96416724a5cc1e8721e0f5))

UDP sockets, TURN relay and TCP forwards, sessions with a local proxy, packet filter (RFC-8), DERP
  home by latency (RFC-4), IPv6 underlay (RFC-2), PCP/NAT-PMP port mapping (RFC-3) and tailnet lock
  (RFC-5).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- **mesh-py**: Python bindings for the mesh node (arkitekt-mesh on PyPI)
  ([`54367ed`](https://github.com/arkitektio/arkitekt-mesh/commit/54367edca6586469eb0f18ec995dd1bd76e40503))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

- **meshd**: Arkitekt-meshd in Rust, replacing the Go tsnet sidecar (RFC-1)
  ([`a63e76c`](https://github.com/arkitektio/arkitekt-mesh/commit/a63e76c9f3e25019015938b4244d6c1e410cb42e))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

### Refactoring

- Move the ESP32 firmware to arkitekt-mesh-esp32
  ([`849d963`](https://github.com/arkitektio/arkitekt-mesh/commit/849d9639eebee8a2a07f6992ab75ba95b00923f7))

The firmware and the ESP32-C6 check now live in github.com/arkitektio/arkitekt-mesh-esp32 and depend
  on arkitekt-mesh by git. CI here checks the feature set they build (mesh-embedded).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1

### Testing

- Local mesh lab against our ionskale fork
  ([`c918f98`](https://github.com/arkitektio/arkitekt-mesh/commit/c918f988e75280623c75e88a8ab3ea304808b002))

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

Claude-Session: https://claude.ai/code/session_011edrvdGLpPzRexTAFMp1v1


## v0.1.0 (2026-09-27)

### Features

- Split into publishable workspace crates with lockstep releases
  ([`f34b12d`](https://github.com/arkitektio/arkitekt-mesh/commit/f34b12d2d62082e2e0f096ed0ce4324f0435af74))

Restructure into fakts, rath, rekuest, rekuest-macros, arkitekt and mikro crates. Publish rath/mikro
  as arkitekt-rath/arkitekt-mikro (names taken on crates.io) while keeping their lib names. Add
  release-plz config for lockstep semantic releases and CI/release workflows on main.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>

- With state and the webserver
  ([`25a7737`](https://github.com/arkitektio/arkitekt-mesh/commit/25a7737e8439acb61c7707df7a5402798c9d73a8))
