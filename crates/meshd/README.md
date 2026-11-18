# arkitekt-meshd

The mesh sidecar for Arkitekt apps. It is a userspace tailnet node built on
[`arkitekt-mesh`](../mesh/), our own Tailscale-compatible client. It joins a
deployment's mesh (ionscale) and exposes:

- a local **HTTP proxy** into the mesh (`CONNECT` plus absolute-form http;
  never SOCKS);
- with `--turn`, a **TURN relay** on 127.0.0.1 that relays over the mesh, so
  WebRTC media (LiveKit) reaches a mesh-only SFU without root or a TUN device;
- with `--forward NAME=host:port`, local **TCP forwards** to mesh hosts;
- with `--peer-relay-port PORT`, a **peer relay**: it forwards UDP on that
  port for pairs of peers that find no direct path to each other, if the
  mesh grants them its use. `--peer-relay-endpoint IP:PORT` (repeatable) says
  where peers reach the port, for a relay behind a port forward.

## Protocol

```
arkitekt-meshd --statedir DIR --hostname NAME [--control-url URL] [--listen 127.0.0.1:0]
               [--timeout 90s] [--tcp-buffer BYTES] [--ephemeral] [--proxy-auth]
               [--turn] [--forward NAME=host:port]... [--no-stdin]
               [--peer-relay-port PORT [--peer-relay-endpoint IP:PORT]...]
```

- **Auth key:** read from `$ARKITEKT_MESH_AUTHKEY`, never from argv. It is
  used only to join; a node already joined in `DIR` ignores it.
- **Control URL:** saved in `DIR`, so restarts may omit `--control-url`.
- **TCP buffer:** per connection, each way (default 1 MiB). A connection's
  throughput is at most this per round trip.
- **Proxy credentials:** with `--proxy-auth` the proxy asks every request
  for credentials, and `proxy` in `ready` carries them
  (`http://mesh:TOKEN@127.0.0.1:PORT`). Without it any user of the machine
  reaches the mesh as this node; a shared machine wants it. Forwards cannot
  ask for credentials.
- **stdout** gets one JSON line when the start is over, and after `ready`
  one more whenever the node's standing with control changes:
  - `{"event":"ready","proxy":"http://127.0.0.1:PORT","hostname":…,"ips":[…],"turn":{"urls":[…],"username":…,"credential":…},"forwards":{"NAME":"127.0.0.1:PORT"}}`
    (`turn`, `forwards` and `peer_relay`, `{"port":…,"addresses":[…]}`,
    appear only when asked for);
  - or `{"event":"error","code":…,"message":…}` with exit code 1. Codes:
    `needs_login`, `locked`, `timeout`, `login`, `start`, `usage`,
    `statedir`, `listen`, `turn`, `forward`, `peer_relay`, and for tailnet lock
    `locked_out` (this node's key is not signed; the message names the
    `nodekey:` to sign) and `lock_unverified`.
  - after `ready`: `{"event":"control","state":…,"reason":…}`. States:
    `connected`; `reconnecting` (it tries again by itself, and runs on with
    the peers it knows); and `key_expired`, `needs_login`, `refused`, which
    take a new login: stop it and join again with an auth key.
- **stderr** gets the logs.
- **Shutdown:** it exits when **stdin closes**, so it never outlives its
  parent. Pass `--no-stdin` to run it interactively.

Prebuilt binaries for every platform are attached to the GitHub releases by
`.github/workflows/meshd.yml`; `cargo install arkitekt-meshd` builds it from
crates.io. (Python apps that want the node without a binary use the
`arkitekt-mesh` package on PyPI, which runs it in-process.)
