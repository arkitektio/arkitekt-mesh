# arkitekt-mesh-web

[arkitekt-mesh](https://github.com/arkitektio/arkitekt-mesh) in the
browser (and node): a node of an Arkitekt deployment's tailnet on wasm32.
A browser has no raw TCP and no UDP, so control and DERP go over
WebSockets and every packet through DERP; TCP to mesh services runs on the
mesh's own netstack.

It is `arkitekt-mesh-embassy` on the JS event loop: `start(config)` runs
the node (`wasm_bindgen_futures::spawn_local`), `Mesh::connect` reaches a
peer, `Mesh::resolve` finds it by name.

The control server must accept the WebSocket forms (`GET /ts2021` with
the `tailscale-control-protocol` subprotocol, `GET /derp` with `derp`) and
let other origins read `/key`: tailscale's test control and our ionskale
do. `checks/web` in the repository runs it under node against both.
