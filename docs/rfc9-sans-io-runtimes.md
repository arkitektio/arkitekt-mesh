# RFC-9: A sans-IO node, driven by tokio, embassy and the browser

**Status:** Proposed (October 2026).

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
- **Control speaks HTTP/2 through the `h2` crate** (std and tokio). The
  control server answers only HTTP/2 after Noise (`testcontrol` serves the
  Noise connection with `http2.Server.ServeConn`; tailscale's
  `controlhttpserver` has no HTTP/1.1 fallback), and there is no no_std
  HTTP/2 client.

The core also uses `std::time::Instant` (≈100 places, mostly
`wg.rs`, `paths.rs`, `netcheck.rs`, `netstack.rs`, `filter.rs`), takes
randomness from `OsRng` (5 files) and keeps `HashMap`s. It has no
`std::io`.

## Decision

The same layering as rekuest's session (arkirust, `rekuest-session`):

```
core (no_std + alloc)          codecs, state machines, NodeCore, ControlConn, DerpConn, HTTP/2
  driver: tokio (std)          sockets, rustls, tasks: Node, TcpStream, Session, proxy, relay
  driver: embassy (no_std)     embassy-net UDP, TLS streams from a connector, embedded-io sockets
  driver: web (wasm32)         DERP and control over WebSocket, no UDP (later, see Phases)
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
  upgrade on the web driver), Noise (exists), then HTTP/2 with register,
  map (streaming, through the existing `MapReader`) and the endpoint updates
  as requests on one connection.
- **DerpConn:** the HTTP upgrade to `derp` (or WebSocket), the framing
  (exists, `derp.rs`), keepalives, the client-info handshake.

### HTTP/2, our own

A client for one connection, as control needs it: the preface, SETTINGS,
HEADERS (+ CONTINUATION), DATA, WINDOW_UPDATE, PING, GOAWAY, RST_STREAM;
client-initiated streams only, no push, no priorities. HPACK in full on the
decoding side (Go's encoder uses the dynamic table and Huffman-codes strings
whenever shorter), static table and literals on the encoding side.

Flow control is the memory bound: a small `SETTINGS_INITIAL_WINDOW_SIZE`
and connection window keep at most that much of a map response in flight,
however large (`MAX_MAP_FRAME` is 16 MiB); the `MapReader` already holds
one peer at a time.

Tested on tokio first, against the `h2` crate as a dev-dependency *server*
(frame-level conformance) and against the Go harness (tailscale's own
control server), before anything else uses it. Whether tokio keeps the `h2`
crate meanwhile is an open question.

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

1. **The core without std.** `mesh::time::Instant`, injected randomness,
   the maps; `std` feature (default) for the std wrappers; the core builds
   for `thumbv7em-none-eabihf` and `xtensa-esp32s3-none-elf` in CI. No
   behaviour change.
2. **NodeCore.** `State` and the loops' policy out of `driver/node.rs`; the
   tokio driver is the thin loop around it. The node, lab, lock and memory
   tests pass unchanged: if one needs more than an import path, the
   extraction changed behaviour.
3. **HTTP/2 and ControlConn.** Our HTTP/2 against the `h2` server in tests,
   then control (register, map, updates, reconnect) on it under tokio,
   against the Go harness.
4. **DerpConn.** The DERP connection machine; tokio's DERP task only moves
   bytes.
5. **The embassy driver.** A conformance run on the host, against the Go
   harness: an embassy executor on std with async-io UDP and TCP (as
   arkirust's `checks/embassy` runs the real stack), rustls-free TLS from a
   connector. The only check before hardware, so it is required. Builds for
   `xtensa-esp32s3-none-elf`.
6. **arkirust and the board.** The joiner contract and the routing
   `TcpConnect` in fakts / arkitekt-embassy (an arkirust release), then the
   `mesh` feature in `esp32-embassy-demo` (S3 + PSRAM).
7. **The web driver** (if wanted): DERP-only over WebSocket, run under node
   against the Go harness's derper and control server.

## Open questions

- **One crate or two:** `arkitekt-mesh` with `std` / `tokio` / `embassy`
  (/ `web`) features (no new publisher), or a separate core crate.
- **HTTP/2 on tokio:** ours everywhere from phase 3 (one implementation,
  tested everywhere), or keep the `h2` crate on tokio and use ours only
  without std.
- **The web driver:** in scope, or not until there is a browser app that
  needs the mesh.
- **headscale:** whether the deployments' control server speaks the same
  (HTTP/2 after Noise, WebSocket for the web driver) is to be checked against
  the version deployed; the Go harness is tailscale's `testcontrol`.

## Risks

- **HTTP/2 against a real server:** HPACK's dynamic table and Huffman
  coding are where clients break. Mitigated by testing against `h2` and Go
  before anything depends on it.
- **The extraction changes behaviour:** the tokio tests are the net, as in
  rekuest; timing-sensitive lab tests (netcheck, rehome) most of all.
- **Memory on the S3:** four TLS connections at once; measured on the host
  first, PSRAM required.
