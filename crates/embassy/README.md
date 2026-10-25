# arkitekt-mesh-embassy

[arkitekt-mesh](https://github.com/arkitektio/arkitekt-mesh) on
[embassy](https://embassy.dev): a node of an Arkitekt deployment's tailnet
without std, for a microcontroller (an ESP32-S3 with PSRAM).

The decisions are `arkitekt-mesh-core`'s (control, DERP, WireGuard,
disco, the netstack, tailnet lock); this crate moves their bytes over
what the app gives it:

- `Udp`: one IPv4 UDP socket (embassy-net's);
- `Dial`: byte streams to `host:port`, TLS or plain (the app's TLS).

`Mesh::run` is the node, one future beside the app's own (no `Send`).
`Mesh` connects TCP over the tunnel (`Mesh::connect`, and
`embedded_nal_async::TcpConnect` and `Dns` with the netmap's names).

`checks/embassy` in the repository runs it on the host against
tailscale's test control server and against ionskale.
