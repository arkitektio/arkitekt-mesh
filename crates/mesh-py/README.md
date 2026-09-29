# arkitekt-mesh (Python)

Runs an Arkitekt mesh node inside the Python process. It uses
[`arkitekt-mesh`](https://github.com/arkitektio/arkirust/tree/main/crates/mesh), our own Tailscale-compatible client in Rust,
the same node the Rust client and `arkitekt-meshd` run. `fakts` uses it
when it is installed; see `MeshOptions.backend`.

```python
from arkitekt_mesh import Node

node = await Node.start("~/.local/state/arkitekt/mesh/my-app-native", "my-app",
                        control_url="https://mesh.example", auth_key="tskey-…")
node.proxy_url                  # "http://127.0.0.1:41234": HTTP proxy into the mesh
turn = await node.turn()        # TURN relay on 127.0.0.1 for WebRTC (LiveKit) media
local = await node.forward("livekit", 7880)   # "127.0.0.1:P" -> livekit:7880 on the mesh
node.close()
```

The node is joined once with an auth key; later starts in the same state
directory need neither the key nor the control url. Errors are subclasses of
`MeshError`: `NeedsLogin`, `Locked`, `Refused` and `Timeout`.
