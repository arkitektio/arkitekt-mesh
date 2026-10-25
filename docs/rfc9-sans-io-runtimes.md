# RFC-9: A sans-IO node, driven by tokio, embassy and the browser

**Status:** Accepted (October 2026): a separate core crate; the `h2` crate
stays on tokio; the web driver is in scope; HTTP/1.1 over Noise on the
runtimes without std, developed together with ionskale.

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
  HTTP/1.1 otherwise, and it flushes every map response, so a map stream
  works over HTTP/1.1 too.

The core also uses `std::time::Instant` (≈100 places, mostly
`wg.rs`, `paths.rs`, `netcheck.rs`, `netstack.rs`, `filter.rs`), takes
randomness from `OsRng` (5 files) and keeps `HashMap`s. It has no
`std::io`.

## Decision

The same layering as rekuest's session (arkirust, `rekuest-session`):

```
arkitekt-mesh-core (no_std + alloc)  codecs, state machines, NodeCore, DerpConn, the control
                                     protocol (upgrade, Noise, register/map), HTTP/1.1 over Noise
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
- **Randomness:** `&mut dyn CryptoRngCore` passed in where keys, nonces,
  STUN transactions and jitter are made. `generate()`-style
  constructors keep a std wrapper over `OsRng`.
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
  tailnet-lock sync as requests, in HTTP/2 or HTTP/1.1 (below).
- **DerpConn:** the HTTP upgrade to `derp` (or WebSocket), the framing
  (exists, `derp.rs`), keepalives, the client-info handshake.

### HTTP over Noise: HTTP/2 on tokio, HTTP/1.1 elsewhere

The control protocol (register, map, the endpoint and tailnet-lock
requests, the `MapReader`) is the core's; how its requests travel is the
driver's:

- **tokio:** HTTP/2 through the `h2` crate, as now: one Noise connection
  carries the map stream and every request. Works with any Tailscale
  control server, and stays tested against tailscale's own (`testcontrol`).
- **embassy and web:** HTTP/1.1 over Noise, the core's (a request writer
  and a response reader: `Content-Length`, chunked, streamed into the
  `MapReader`). One request at a time per connection, and the map stream
  never ends, so the stream has a connection of its own and register,
  endpoint updates and tailnet-lock sync go over a second one, made when
  needed and closed after. The stream keeps running meanwhile; nothing is
  re-downloaded.

HTTP/1.1 over Noise is what ionskale gives today (its `h2c` handler). It
is developed together with ionskale from here: an ionskale test keeps it
working (register, a streamed map, a lite update, over HTTP/1.1 on Noise and
on Noise in a WebSocket), and the conformance runs of the no-std drivers go
against ionskale, not `testcontrol` (which has no HTTP/1.1).

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
| A map response in memory | one peer at a time (`MapReader`) |
| The request connection to control | 33 KiB more while it is open |

About 200 KiB of heap before the app (230 while a request connection is open): an **ESP32-S3 with PSRAM**. The
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

1. **The core crate, without std.** `arkitekt-mesh-core` takes the codecs
   and state machines; `mesh::time::Instant`, injected randomness, the
   maps; it builds for `thumbv7em-none-eabihf` and `xtensa-esp32s3-none-elf`
   in CI. `arkitekt-mesh` re-exports it at the old paths. No behaviour
   change. (A new crate: a crates.io placeholder and trusted publisher
   before the release.)
2. **NodeCore.** `State` and the loops' policy out of `driver/node.rs`; the
   tokio driver is the thin loop around it. The node, lab, lock and memory
   tests pass unchanged: if one needs more than an import path, the
   extraction changed behaviour.
3. **ionskale in the harness; HTTP/1.1 over Noise.** ionskale gets its test
   for HTTP/1.1 (and WebSocket) on Noise; the mesh harness can start an
   ionskale (the `mounts/ionskale` build) beside `testcontrol`. The core's
   control protocol and HTTP/1.1 client, tested against ionskale on the host.
4. **DerpConn.** The DERP connection machine (and over WebSocket); tokio's
   DERP task only moves bytes.
5. **The embassy driver.** A conformance run on the host against ionskale:
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
- **HTTP/2 on tokio stays the `h2` crate**; the runtimes without std speak
  HTTP/1.1 over Noise (above), so there is no HTTP/2 of our own.
- **The web driver is in scope** (phase 6).
- **The control server is ionskale**, maintained by us: what the no-std
  drivers need from it (HTTP/1.1 and WebSocket on Noise) is tested there.

## Risks

- **HTTP/1.1 ties the no-std drivers to ionskale:** another control server
  (tailscale's, headscale) may answer only HTTP/2 after Noise. Tolerable
  while ionskale is the deployments' server; an HTTP/2 of our own would lift
  it later.
- **The extraction changes behaviour:** the tokio tests are the net, as in
  rekuest; timing-sensitive lab tests (netcheck, rehome) most of all.
- **Memory on the S3:** four TLS connections at once; measured on the host
  first, PSRAM required.
