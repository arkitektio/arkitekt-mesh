# RFC-9: A sans-IO node, driven by tokio, embassy and the browser

**Status:** Accepted (October 2026): a separate core crate; the `h2` crate
stays on tokio, an HTTP/2 client of our own (sans-IO, in the core) for the
runtimes without std; the web driver is in scope; developed together with
ionskale, our control server.

## Problem

The mesh runs where tokio runs: desktops, servers, Python, and the ESP32
on ESP-IDF (std + tokio, `esp32-mesh-demo` and `arkitekt-esp32-rs`). It
does not run on embassy (no std, no ESP-IDF), where `esp32-embassy-demo`
now provisions over BLE, joins eduroam and serves an Arkitekt agent; nor in
a browser.

The codecs and state machines are already sans-IO (Noise, the map
reader, WireGuard, disco, paths, the netstack, the filter, tailnet lock),
but two things keep them on tokio:

- **The node is three tokio tasks.** `driver/node.rs` (1.8k lines) holds,
  inside `tokio::select!` loops, decisions that are protocol, not I/O:
  re-homing on latency, the STUN schedule, which endpoints to report and
  when, DERP backpressure, rebinding, the map stream's reconnect and
  backoff, tailnet-lock sync, peer eviction. Another runtime would have to
  copy them.
- **Control speaks HTTP/2 through the `h2` crate** (std and tokio), and
  there is no no_std HTTP/2 client. Tailscale's `testcontrol` (the Go
  harness) answers only HTTP/2 after Noise (`http2.Server.ServeConn`). Our
  control server, ionskale, serves the Noise connection with
  `h2c.NewHandler`: HTTP/2 for a client that opens with the preface,
  HTTP/1.1 otherwise. We speak HTTP/2 everywhere all the same: HTTP/1.1
  would tie the drivers without std to that fallback (tailscale's server and
  headscale have none), and HTTP/2 carries the map stream and the requests
  on one connection.

The core also uses `std::time::Instant` (≈100 places, mostly
`wg.rs`, `paths.rs`, `netcheck.rs`, `netstack.rs`, `filter.rs`), takes
randomness from `OsRng` (5 files) and keeps `HashMap`s. It has no
`std::io`.

## Decision

The same layering as rekuest's session (arkirust, `rekuest-session`):

```
arkitekt-mesh-core (no_std + alloc)  codecs, state machines, NodeCore, DerpConn, the control
                                     protocol (upgrade, Noise, register/map), an HTTP/2 client
arkitekt-mesh                        the drivers, by feature:
  tokio (std)                        sockets, rustls, HTTP/2 (the h2 crate): Node, TcpStream,
                                     Session, proxy, relay; unchanged for meshd, mesh-py, fakts
  embassy (no_std)                   embassy-net UDP, TLS streams from a connector, embedded-io sockets
  web (wasm32)                       DERP and control over WebSocket, no UDP
```

Every driver runs the one `NodeCore`; a driver only moves bytes, keeps
time and spawns its connections.

### Shared types (fixed first)

- **Time:** `mesh::time::Instant`, microseconds since an arbitrary epoch
  (`u64`), with `Duration` arithmetic; drivers convert from
  `std::time::Instant`, `embassy_time::Instant` or the JS clock. The
  netstack converts to `smoltcp::time::Instant` at its edge.
- **Randomness and the wall clock:** platform hooks, as arkirust's runtime
  interface: `random::set_source` and `time::set_wall_clock` (WireGuard's
  TAI64N handshake timestamps), installed once by a driver without std;
  with std, `OsRng` and `SystemTime`. Monotonic time stays an argument, so
  tests stay deterministic.
- **Maps:** `BTreeMap` (small, ordered, deterministic in tests), or
  hashbrown where a large tailnet makes it matter (`paths`, `wg`).
- **smoltcp:** 0.13.1, which embassy-net 0.9 uses too: one copy on a board.
- **Errors:** `core::error::Error`; `thiserror` without std.

### NodeCore

`State` and the bodies of `run_loop`, `map_loop`, `update_loop` and
`rehome` move into one state machine in the quinn-proto pattern: inputs
change it, outputs are polled.

```rust
NodeCore::new(config, identity, rng, now)
// inputs
handle_datagram(now, local: Local, src: SocketAddr, data: &[u8])  // UDP v4/v6
handle_derp(now, region, DerpInput)        // connected, frame bytes, closed
handle_control(now, ControlInput)          // connected, bytes, closed
handle_timeout(now)
rebind(now)                                // a new network (the driver made new sockets)
// the app's sockets (on the netstack)
tcp_connect / tcp_listen / tcp_read / tcp_write / tcp_close, udp_bind / …
// outputs
poll_transmit() -> Option<Transmit>        // Udp { local, dst, data } | Derp { region, data } | Control { data }
poll_event() -> Option<Event>              // ConnectDerp { region, url } | DropDerp | ConnectControl { url }
                                           // | DropControl | Joined | NetmapChanged | Ended(error)
poll_timeout() -> Option<Instant>
```

The policy moves with it, unchanged: STUN every 20 s with jitter, netcheck
at the configured interval, home by latency with hysteresis (RFC-4),
endpoints reported to control only when they change, DERP queue
backpressure (sockets held back while the fullest connected region's queue
is full), the 120 s quiet limit on control and DERP, reconnect with backoff
1 s → 30 s, tailnet lock synced before a netmap change is applied (RFC-5),
the peer cap.

### ControlConn and DerpConn

Sans-IO connection machines the core owns, fed bytes from whatever the
driver's TLS (or plain TCP, or WebSocket) stream gives:

- **ControlConn:** `GET /key`, the `POST /ts2021` upgrade (or a WebSocket
  upgrade on the web driver), Noise (exists), then register, map
  (streaming, through the existing `MapReader`), the endpoint updates and
  tailnet-lock sync as requests on one HTTP/2 connection (below).
- **DerpConn:** the HTTP upgrade to `derp` (or WebSocket), the framing
  (exists, `derp.rs`), keepalives, the client-info handshake.

### HTTP/2: the h2 crate on tokio, our own elsewhere

The control protocol (register, map, the endpoint and tailnet-lock
requests, the `MapReader`) is the core's; its requests travel over HTTP/2
on every driver:

- **tokio:** the `h2` crate, as now.
- **embassy and web:** an HTTP/2 client of our own in the core, sans-IO,
  for one connection as control needs it: the preface, SETTINGS, HEADERS
  (+ CONTINUATION), DATA, WINDOW_UPDATE, PING, GOAWAY, RST_STREAM;
  client-initiated streams only, no push, no priorities. HPACK in full on the
  decoding side (Go's encoder uses the dynamic table and Huffman-codes strings
  whenever shorter), static table and literals on the encoding side.

Flow control is the memory bound: a small `SETTINGS_INITIAL_WINDOW_SIZE`
and connection window keep at most that much of a map response in flight,
however large (`MAX_MAP_FRAME` is 16 MiB); the `MapReader` holds one peer at
a time.

Ours is tested before anything uses it: frame by frame against the `h2`
crate as a dev-dependency server, then against tailscale's `testcontrol`
(the Go harness) and against ionskale, under tokio. ionskale also gets a
test that the WebSocket upgrade on Noise (what the web driver uses) keeps
working.

### Drivers

- **tokio:** `Node`, `TcpStream`, `TcpListener`, `UdpSocket`, `Session`,
  the proxy, the relay and port mapping keep their API; underneath, one task
  owns the core and the UDP sockets, one task per control and DERP
  connection moves bytes through rustls. meshd, mesh-py and fakts change
  nothing.
- **embassy:** UDP through embassy-net (IPv4; IPv6 off, as on `Limits::small`).
  TLS streams for control and DERP come from a connector the app gives
  (`embedded_io_async::Read + Write`): arkitekt-embassy's TLS 1.3
  (`conn::open`), so the mesh does not depend on arkirust. For the app, the
  driver offers `embedded_nal_async::TcpConnect` and `Dns` over the tunnel
  (MagicDNS names from the netmap), so anything built on embedded-nal-async
  (arkitekt-embassy's `serve_http` and agent) reaches mesh services
  unchanged. No `Send` bound, as rekuest's link.
- **web (later):** no UDP in a browser: DERP-only, control and DERP over
  WebSocket (tailscale's control server and derper accept the upgrade; its
  own js client does this). Sockets over the netstack as for embassy.

### arkirust: the joiner without a proxy

fakts' `MeshJoiner::join` returns the local HTTP proxy
(`http://127.0.0.1:<port>`); without std there is no loopback proxy. The
contract gains a second answer: the platform reaches mesh addresses itself.
On embassy the app routes with a combinator `TcpConnect`: tailnet addresses
and MagicDNS names over the mesh, everything else over embassy-net, given
to `serve_http` and `Board` as their TCP. A coordinated arkirust release
(fakts, arkitekt-embassy).

## Memory on a board

Persistent while on the mesh, besides Wi-Fi (≈50 KiB):

| | |
|---|---|
| TLS to control and to the home DERP region | 2 × 33 KiB (records) |
| TLS of the login and the agent (arkirust) | 2 × 33 KiB |
| The netstack at `Limits::small` | 8 KiB per TCP socket each way, 16 peers |
| HTTP/2 map window | the window chosen (e.g. 16 KiB) |

About 200 KiB of heap before the app: an **ESP32-S3 with PSRAM**. The
classic ESP32 (≈112 KiB of heap with BLE) is out. Measured first on the
host with `tests/memory.rs` under `Limits::small`, before any firmware.

## Stays std-only

- `Session` (state directory, identity file, the hyper proxy), the relay
  (TURN, webrtc-util), port mapping's socket side for now (its PCP and
  NAT-PMP codec is already in the core and comes along cheaply).
- `tka-disable` (Argon2i at 16 MiB): a board in a tailnet whose lock was
  disabled stays locked, fail-closed.

## Phases

Each phase ends green and could be released. Gates every time:
`cargo test` (core, Go harness, lab), meshd, mesh-py, arkirust fakts with
`mesh`, `mesh-native` and `mesh-relay`, the ESP-IDF firmware with
`--features mesh`, `esp32-mesh-demo`.

1. **The core crate, without std** (done: builds for `thumbv7em-none-eabihf`,
   `wasm32-unknown-unknown` and `xtensa-esp32s3-none-elf`; every test
   unchanged). `arkitekt-mesh-core` takes the codecs
   and state machines; `mesh::time::Instant`, injected randomness, the
   maps; it builds for `thumbv7em-none-eabihf` and `xtensa-esp32s3-none-elf`
   in CI. `arkitekt-mesh` re-exports it at the old paths. No behaviour
   change. (A new crate: a crates.io placeholder and trusted publisher
   before the release.)
2. **NodeCore** (done: `mesh_core::node`, and tailnet lock's state in
   `mesh_core::lock`; the DERP queues stay with the driver, which tells the
   core the fullest one's room; every test unchanged). `State` and the loops' policy out of `driver/node.rs`; the
   tokio driver is the thin loop around it. The node, lab, lock and memory
   tests pass unchanged: if one needs more than an import path, the
   extraction changed behaviour.
3. **HTTP/2 and the control protocol in the core.** Our HTTP/2 against the
   `h2` server in tests, then the control protocol on it, against
   `testcontrol` and ionskale (the mesh harness can start the
   `mounts/ionskale` build), on the host. ionskale gets its WebSocket-on-Noise
   test.
4. **DerpConn.** The DERP connection machine (and over WebSocket); tokio's
   DERP task only moves bytes.
5. **The embassy driver.** A conformance run on the host against
   `testcontrol` and ionskale:
   an embassy executor on std with async-io UDP and TCP (as arkirust's
   `checks/embassy` runs the real stack), TLS from a connector. The only
   check before hardware, so it is required. Builds for
   `xtensa-esp32s3-none-elf`.
6. **The web driver.** DERP-only, control and DERP over WebSocket; run
   under node against ionskale, like arkirust's wasm e2e.
7. **arkirust and the board.** The joiner contract and the routing
   `TcpConnect` in fakts / arkitekt-embassy (an arkirust release), then the
   `mesh` feature in `esp32-embassy-demo` (S3 + PSRAM).

## Decided

- **A separate core crate**, `arkitekt-mesh-core`; the drivers stay in
  `arkitekt-mesh` by feature.
- **HTTP/2 everywhere:** the `h2` crate on tokio, our own in the core for
  the runtimes without std (not HTTP/1.1, which only ionskale's `h2c`
  fallback would take).
- **The web driver is in scope** (phase 6).
- **The control server is ionskale**, maintained by us: what the drivers
  need from it (WebSocket on Noise for the web driver) is tested there, and
  the conformance runs go against it as well as `testcontrol`.

## Risks

- **HTTP/2 against a real server:** HPACK's dynamic table and Huffman
  coding are where clients break. Mitigated by testing against `h2`,
  `testcontrol` and ionskale before anything depends on it.
- **The extraction changes behaviour:** the tokio tests are the net, as in
  rekuest; timing-sensitive lab tests (netcheck, rehome) most of all.
- **Memory on the S3:** four TLS connections at once; measured on the host
  first, PSRAM required.
