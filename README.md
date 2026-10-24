# arkitekt-mesh

Our own Tailscale-compatible mesh client in Rust, written from the protocol
up. Arkitekt apps use it to reach instances that a deployment serves only
over its private mesh (an ionscale tailnet). The Arkitekt clients built on it
live in [arkitektio/arkirust](https://github.com/arkitektio/arkirust) (the
`fakts` crate's `mesh-native` and `mesh-relay` features) and in the Python
`fakts` package.

| Crate | Published as | What |
|---|---|---|
| [`crates/mesh`](crates/mesh/) | `arkitekt-mesh` on crates.io (imported as `mesh`) | The node: control, WireGuard, DERP, disco, the local proxy and the relay |
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
  network allows and relay through DERP when it doesn't.

The same limits apply to any new implementation:

* It has not been audited. The protocols are tested against tailscale's own Go
  implementation (see below), and the cryptographic primitives come from the
  RustCrypto crates.
* It has no MagicDNS. Mesh hostnames are looked up in the node's netmap by
  hostname or FQDN.
* It dials out only. The node accepts no inbound TCP connections; a UDP
  socket it binds (`Node::bind_udp`) receives only what peers send to it.

The crate's end-to-end tests (`cargo test -p arkitekt-mesh`) run it against
tailscale's test control server, a DERP/STUN server and a `tsnet` peer. They
build these from `crates/mesh/tests/harness` and need Go; without Go they are
skipped.

For running the same stack on an ESP32, see
[arkitektio/arkitekt-mesh-esp32](https://github.com/arkitektio/arkitekt-mesh-esp32).

Go appears only in the tests, as the reference tailscale the client is
checked against. The client used to run as a Go tsnet sidecar; that build is
gone (see [RFC-1](docs/rfc1-rust-only-mesh.md)). What the Rust node lacked compared with tsnet
is tracked as RFCs, each listing what is done and what is not:

| RFC | What | Status |
|---|---|---|
| [RFC-2](docs/rfc2-ipv6-underlay.md) | Direct paths over IPv6 | Implemented |
| [RFC-3](docs/rfc3-nat-port-mapping.md) | NAT port mapping | PCP and NAT-PMP; no UPnP |
| [RFC-4](docs/rfc4-derp-home-by-latency.md) | Home DERP region by measured latency | Implemented |
| [RFC-5](docs/rfc5-tailnet-lock.md) | Tailnet lock | Verifying node; no signing or fork resolution |
| [RFC-6](docs/rfc6-cross-platform.md) | macOS and Windows | Tests green on all three; release signing open |
| [RFC-7](docs/rfc7-production-and-throughput.md) | Production and throughput | Proposed |
| [RFC-8](docs/rfc8-packet-filter.md) | Enforcing the tailnet's ACLs | Implemented |

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
testing/mesh-lab/lab.sh up && testing/mesh-lab/lab.sh test --python
```

The history up to v0.7.0 was developed inside arkirust and was split out with
its commits intact.
