# arkitekt-mesh

Our own Tailscale-compatible mesh client in Rust, written from the protocol
up. Arkitekt apps use it to reach instances that a deployment serves only
over its private mesh (an ionscale tailnet). The Arkitekt clients built on it
live in [arkitektio/arkirust](https://github.com/arkitektio/arkirust) (the
`fakts` crate's `mesh-native` and `mesh-relay` features) and in the Python
`fakts` package.

| Crate | Published as | What |
|---|---|---|
| [`crates/core`](crates/core/) | `arkitekt-mesh-core` on crates.io | The protocols without I/O (no_std + alloc): codecs and state machines every driver shares |
| [`crates/mesh`](crates/mesh/) | `arkitekt-mesh` on crates.io (imported as `mesh`) | The node on tokio: control, WireGuard, DERP, disco, the local proxy and the relay |
| [`crates/embassy`](crates/embassy/) | `arkitekt-mesh-embassy` on crates.io | The node without std, on embassy (microcontrollers) |
| [`crates/web`](crates/web/) | `arkitekt-mesh-web` on crates.io | The node in the browser (WebSockets, DERP only) |
| [`crates/smoltcp`](crates/smoltcp/) | `arkitekt-mesh-smoltcp` on crates.io | Our smoltcp fork: SACK recovery and buffers that grow (`fast-tcp`) |
| [`crates/meshd`](crates/meshd/) | `arkitekt-meshd` on crates.io, binaries on the GitHub releases | The sidecar: a userspace node behind a local HTTP proxy (`--turn` and `--forward` also expose the relay and forwards) |
| [`crates/mesh-py`](crates/mesh-py/) | `arkitekt-mesh` on PyPI | Python bindings: the same node in-process |

## The client

The node speaks:

* ts2021 control (Noise, then HTTP/2), the protocol ionscale, headscale and
  Tailscale serve. It is tested against tailscale's own test control server,
  and against our ionskale fork in the local mesh lab (`testing/mesh-lab`),
* WireGuard,
* DERP relays,
* disco path discovery with STUN, so peers get direct UDP paths when the
  network allows and relay through DERP when it doesn't,
* peer relays: where no direct path is found and the tailnet has a node
  that relays UDP, the path goes through it, not through DERP
  ([RFC-10](docs/rfc10-peer-relays.md)).

The same limits apply to any new implementation:

* It has not been audited. The protocols are tested against tailscale's own Go
  implementation (see below), and the cryptographic primitives come from the
  RustCrypto crates.
* It has no MagicDNS. Mesh hostnames are looked up in the node's netmap by
  hostname or FQDN.
* Inbound is what an app asks for: TCP on a port it listens on
  (`Node::listen`) and UDP on a socket it binds (`Node::bind_udp`), from the
  peers the tailnet's ACLs allow.

A running node says how it stands with control (`Node::control_state`,
`control()` in Python, `control` events from meshd): it reconnects by
itself, but a node whose key expired or that was removed needs a new login,
and its view of the mesh goes stale until then.

The local proxy is this node to whoever reaches its port. On a machine with
other users, have it ask for credentials (`Session::serve_proxy_with`,
`proxy_auth=True` in Python, `--proxy-auth` for meshd); its url then carries
them.

### Restricted networks

* **A network that re-signs outbound TLS** (an institute's inspecting
  gateway): the node trusts the system's certificate store beside the bundled
  public roots (feature `os-roots`, on by default), so a CA installed there is
  enough. `SSL_CERT_FILE` and `SSL_CERT_DIR` name a store, and
  `ARKITEKT_MESH_CA_FILE` adds a PEM file of its own.
* **A network that lets nothing out but through an HTTP proxy**: control and
  DERP are dialed through it with `CONNECT`, as `HTTPS_PROXY` (or
  `ALL_PROXY`) names it, `http://[user:password@]host:port`; `NO_PROXY`
  exempts hosts, domains and networks. Basic credentials only. UDP has no
  proxy, so such a node runs over DERP.

The crate's end-to-end tests (`cargo test -p arkitekt-mesh`) run it against
tailscale's test control server, a DERP/STUN server and a `tsnet` peer. They
build these from `crates/mesh/tests/harness` and need Go; without Go they are
skipped.

For running the same stack on an ESP32, see
[arkitektio/esp32-mesh-demo](https://github.com/arkitektio/esp32-mesh-demo).

Go appears only in the tests, as the reference tailscale the client is
checked against. The client used to run as a Go tsnet sidecar; that build is
gone (see [RFC-1](docs/rfc1-rust-only-mesh.md)). What the Rust node lacked compared with tsnet
is tracked as RFCs, each listing what is done and what is not:

| RFC | What | Status |
|---|---|---|
| [RFC-2](docs/rfc2-ipv6-underlay.md) | Direct paths over IPv6 | Implemented |
| [RFC-3](docs/rfc3-nat-port-mapping.md) | NAT port mapping | PCP, NAT-PMP and UPnP IGD |
| [RFC-4](docs/rfc4-derp-home-by-latency.md) | Home DERP region by measured latency | Implemented |
| [RFC-5](docs/rfc5-tailnet-lock.md) | Tailnet lock | Verifying node; no signing or fork resolution |
| [RFC-6](docs/rfc6-cross-platform.md) | macOS and Windows | Tests green on all three; release signing open |
| [RFC-7](docs/rfc7-production-and-throughput.md) | Production and throughput | Benchmarked and tuned; the production canary is open |
| [RFC-8](docs/rfc8-packet-filter.md) | Enforcing the tailnet's ACLs | Implemented |
| [RFC-9](docs/rfc9-sans-io-runtimes.md) | The core without I/O, and its other runtimes | See the RFC |
| [RFC-10](docs/rfc10-peer-relays.md) | Paths through peer relays | The client; no relay server of our own |

## Releasing

All crates are released in lockstep from Conventional Commits: every push to
main with a `feat`, `fix` or `perf` is a release (semantic-release, see
`releaserc.toml`). The release job publishes the crates, then starts
`release.yaml` (the Python bindings to PyPI, see
[docs/releasing-python.md](docs/releasing-python.md)) and `meshd.yml` (the
`arkitekt-meshd` binaries on the GitHub release).

## Development

```sh
cargo test --workspace                                # Go harness tests skip without Go
cargo test -p arkitekt-mesh --features session,relay
cargo +nightly fuzz run datagrams                     # or `streams`; needs cargo-fuzz
testing/mesh-lab/lab.sh up && testing/mesh-lab/lab.sh test --python
```

The history up to v0.7.0 was developed inside arkirust and was split out with
its commits intact.
