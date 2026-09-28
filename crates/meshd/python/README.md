# arkitekt-meshd

The prebuilt `arkitekt-meshd` sidecar (`crates/meshd`): a userspace tailnet
node built on `arkitekt-mesh`, our own Tailscale-compatible client in Rust.
It joins an Arkitekt deployment's mesh and exposes a local HTTP proxy into it,
and optionally a TURN relay and TCP forwards (`--turn`, `--forward`).
`fakts`' sidecar backend runs it; `arkitekt_meshd.binary_path()` returns the
bundled executable.

To run the node inside Python instead, with no subprocess, install
`arkitekt-mesh`: fakts then picks the in-process node.
