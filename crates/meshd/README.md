# arkitekt-meshd

The mesh sidecar for Arkitekt apps. It is a userspace tailnet node built on
[`arkitekt-mesh`](../mesh/), our own Tailscale-compatible client. It joins a
deployment's mesh (ionscale) and exposes:

- a local **HTTP proxy** into the mesh (`CONNECT` plus absolute-form http;
  never SOCKS);
- with `--turn`, a **TURN relay** on 127.0.0.1 that relays over the mesh, so
  WebRTC media (LiveKit) reaches a mesh-only SFU without root or a TUN device;
- with `--forward NAME=host:port`, local **TCP forwards** to mesh hosts.

## Protocol

```
arkitekt-meshd --statedir DIR --hostname NAME [--control-url URL] [--listen 127.0.0.1:0]
               [--timeout 90s] [--tcp-buffer BYTES] [--ephemeral] [--turn]
               [--forward NAME=host:port]... [--no-stdin]
```

- **Auth key:** read from `$ARKITEKT_MESH_AUTHKEY`, never from argv. It is
  used only to join; a node already joined in `DIR` ignores it.
- **Control URL:** saved in `DIR`, so restarts may omit `--control-url`.
- **TCP buffer:** per connection, each way (default 1 MiB). A connection's
  throughput is at most this per round trip.
- **stdout** gets exactly one JSON line:
  - `{"event":"ready","proxy":"http://127.0.0.1:PORT","hostname":…,"ips":[…],"turn":{"urls":[…],"username":…,"credential":…},"forwards":{"NAME":"127.0.0.1:PORT"}}`
    (`turn` and `forwards` appear only when asked for);
  - or `{"event":"error","code":…,"message":…}` with exit code 1. Codes:
    `needs_login`, `locked`, `timeout`, `login`, `start`, `usage`,
    `statedir`, `listen`, `turn`, `forward`, and for tailnet lock
    `locked_out` (this node's key is not signed; the message names the
    `nodekey:` to sign) and `lock_unverified`.
- **stderr** gets the logs.
- **Shutdown:** it exits when **stdin closes**, so it never outlives its
  parent. Pass `--no-stdin` to run it interactively.

Wheels carrying the binary (`pip install arkitekt-meshd`) are built from
`python/` by `.github/workflows/meshd.yml`.
