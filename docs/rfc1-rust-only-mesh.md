# RFC-1: One mesh client, ours; Go only as the reference in tests

**Status:** Implemented (September 2026).
**Supersedes:** the Go `meshd/` sidecar (tsnet), which was never released.

## Decision

The mesh node is our own Tailscale-compatible client (`crates/mesh`,
`arkitekt-mesh`), everywhere it runs:

| Where | How |
|---|---|
| Rust apps, sidecar backend | `arkitekt-meshd` (`crates/meshd`), the same stdin/stdout protocol |
| Rust apps, native backend | in-process (`fakts` feature `mesh-native`) |
| Python | in-process (`arkitekt-mesh`, `crates/mesh-py`), or the `arkitekt-meshd` wheel (the Rust binary) |
| ESP32 | [arkitekt-mesh-esp32](https://github.com/arkitektio/arkitekt-mesh-esp32) |

Go stays in two places, both test-only and never shipped:
- `crates/mesh/tests/harness`: tailscale's own test control server, DERP/STUN and a tsnet peer;
- `testing/mesh-lab/peer`: the lab's reference peer.

Testing against the real tailscale code is what keeps our client compatible.
Removing it would remove the conformance check.

## Why

- **One implementation to understand, fix and test.** The Go sidecar and the
  Rust node had drifted: only Rust has the TURN relay and forwards (WebRTC
  media) and runs on the ESP32, and the two used different state formats.
- **Smaller and simpler to ship.** A static `arkitekt-meshd` is 8.6 MB against
  22 MB for tsnet, and there is no Go toolchain in the release.
- **Nothing to migrate.** The Go sidecar was never released, so no deployed
  node carries tsnet state.

## What was given up

What tsnet does and our node does not yet do is tracked as RFCs 2–8. None
of it blocks the sidecar's role, because DERP always works as a fallback:
- the IPv6 underlay (RFC-2);
- NAT port mapping (RFC-3);
- choosing the home DERP region by latency (RFC-4);
- tailnet lock (RFC-5);
- verified macOS and Windows builds (RFC-6);
- a production and throughput track record (RFC-7);
- enforcing ACLs on the node (RFC-8).

## Done

- `meshd/` (Go) deleted. The `arkitekt-meshd` wheel packaging moved to
  `crates/meshd/python` and carries the Rust binary.
- `.github/workflows/meshd.yml` builds only Rust: binaries for six targets,
  the `arkitekt-meshd` and `arkitekt-mesh` wheels, and `THIRD_PARTY_LICENSES`.
- fakts (Rust and Python) no longer looks for tsnet's `tailscaled.state`.
