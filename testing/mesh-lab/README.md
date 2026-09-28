# Mesh lab

Local integration tests for our mesh stack against the real control server:
our ionskale fork (built from `deployments/next/mounts/ionskale`), a tsnet
peer, and an NTP server for boards without internet. It covers the Rust
node (`arkitekt-mesh`), `arkitekt-meshd`, the Python bindings and the ESP32
firmware. The Go harness in `crates/mesh/tests/harness` stays the fast,
hermetic check. The lab checks the parts that differ against the real
server:
- TLS with verified certificates;
- ionskale's capability version and map deltas;
- its DERP and STUN;
- key expiry and restarts.

```sh
./lab.sh up                      # ionskale + lab-peer; writes .lab/env
./lab.sh test --python           # every lab suite, then prune the test machines
```

Or piece by piece:

```sh
eval "$(./lab.sh env)"
cargo test -p arkitekt-mesh --features session,relay --test lab --test lab_restart \
  --test lab_firmware_tls --test lab_acl --test lab_lock
cargo test -p arkitekt-meshd --test lab
(cd crates/mesh-py && maturin develop && pytest tests/test_lab.py)
```

Without the lab's environment these tests skip, so plain `cargo test` is
unaffected.

## What runs

| Service | What |
|---|---|
| `ionskale` | `https://<lab addr>:8443`: control, the embedded DERP (same port) and STUN (3478/udp). SQLite in a volume, a fixed admin key in `.lab/admin-key`. |
| `peer` | `lab-peer` on tailnet `lab`: HTTP on :80 (`hello from peer`), TCP and UDP echo on :7. Built with `MESH_LAB_TS_VERSION` of tailscale (default v1.102.5), to test against other client versions. |
| `ts-livekit` + `livekit` | Only with `./lab.sh livekit`: a LiveKit server on the mesh alone (`lab-livekit:7880`, dev keys). tailscaled with a real TUN interface, and livekit-server in its network, offering ICE candidates on the tailnet address only. |
| `lock-admin` | Only with `./lab.sh lock`: a real tailscaled in the `lab-lock` tailnet. It ran `tailscale lock init`, holds the trusted key, and signs node keys (`./lab.sh lock-sign nodekey:…`). |
| `ntp` | Only with `esp32-env`: chrony on 123/udp, so a board without internet can set its clock. |

The lab address is this machine's LAN address by default (`MESH_LAB_ADDR`
overrides it). The host, the containers and a board on the LAN or on PPP
all reach ionskale there. TLS comes from a lab CA (ECDSA P-256) in
`.lab/tls/`.
- Rust clients trust it through `ARKITEKT_MESH_CA_FILE`, set by `lab.sh env`,
  or through `mesh::driver::net::add_trust_roots_pem`.
- Go (the peer) trusts it through `SSL_CERT_FILE`.

## What the tests cover

- `crates/mesh/tests/lab.rs`:
  - joining, then reaching the peer by name, by IP and by FQDN;
  - a 1 MiB TCP echo;
  - UDP over DERP only, and over a direct path (asserted);
  - netmap deltas (a node that joins is seen);
  - the TURN relay to the peer's UDP echo;
  - a `Session` rejoining without a key or url.
- `crates/mesh/tests/lab_restart.rs` (run one at a time):
  - a node survives an ionskale restart: DERP and the map stream reconnect;
  - an expired node key gives `NeedsLogin`, and a new key rejoins.
- `crates/mesh/tests/lab_firmware_tls.rs`: the ESP32 firmware's TLS setup on the
  host. That is `rustls-rustcrypto`, only the lab CA, `Limits::small()`, DERP
  only; it catches TLS problems before a board is flashed.
- `crates/mesh/tests/lab_acl.rs`: ACL enforcement on the `lab-acl` tailnet
  (lok's shape: `tag:app` → `tag:hub:80` only).
- `crates/mesh/tests/lab_lock.rs` (after `./lab.sh lock`): tailnet lock on the
  `lab-lock` tailnet.
  - An unsigned session is refused, naming its key.
  - Once `lock-admin` signs it, the node restarts on its saved chain.
  - Signed nodes reach each other; an unsigned one stays hidden.
- `crates/meshd/tests/lab.rs`: the binary's proxy, TURN and forwards.
- `crates/lovekit/tests/lab_livekit.rs` (after `./lab.sh livekit`): video to
  LiveKit through the UDP tunnel. Two mesh nodes join a room via a local
  forward and their TURN relay (relay-only ICE), one publishes, and the other
  must decode the frames. LiveKit's logs show the selected pairs: its tailnet
  address against a `udp relay` candidate at the node's mesh address.
- `crates/mesh-py/tests/test_lab.py`: the Python node's proxy, forward and TURN.

## ESP32

```sh
./lab.sh esp32-env ../../firmware/esp32-mesh/mesh.env
(cd ../../firmware/esp32-mesh && . ~/export-esp-1.93.sh && cargo build --release \
  && espflash flash --partition-table partitions.csv target/xtensa-esp32-espidf/release/esp32-mesh)
./lab.sh esp32-watch                  # PPP: logs arrive over UDP 5514
./lab.sh esp32-watch --serial /dev/ttyUSB0   # Wi-Fi: logs on the serial port
```

`esp32-env` does four things:
- mints a fresh key;
- points the firmware at the lab (`MESH_CONTROL_URL`, `MESH_PEER=lab-peer`);
- embeds the lab CA (`MESH_CA_PEM_FILE`; with `MESH_CA_ONLY=true`, the
  default, it is trusted instead of the public roots, which saves heap);
- sets the clock source (`MESH_SNTP_SERVER`) and starts the lab's NTP.

It keeps your `WIFI_*`, `MESH_LINK`, PPP and `MESH_DIRECT` lines.

`esp32-watch` waits for the firmware's `MESH-TEST ok peers=… path=… heap_low=…`
line (exit 0), or times out (exit 1). It binds the UDP log port itself, so
stop any `socat` listening there first.

Control and DERP both verify the lab's certificate, so the board needs the
embedded CA *and* a set clock before it joins.

The lab has three tailnets:
- `lab`: test nodes, the peer, LiveKit and boards;
- `lab-acl`: a lok-shaped ACL;
- `lab-lock`: tailnet lock.

Never lock `lab` itself, which would lock out the board and every other
test.

The `lab` tailnet's ACL keeps boards apart from test runs:
- boards carry `tag:esp32` and reach only `lab-peer` (`tag:peer`);
- test nodes (`tag:lab`) never reach a board;
- to reach a board (e.g. its `/status`), use a `tag:probe` key:
  `./lab.sh key --tag tag:probe`.

A netmap lists only peers a node can reach or be reached by, so a board's
netmap stays small however many test nodes come and go.

Restarting `pppd` resets the board: the USB serial adapter's DTR/RTS lines
drive the ESP32's EN/IO0 auto-reset. So a `pppd` restart cannot be used to
test a rebind.

## Admin

```sh
./lab.sh key --ephemeral --tag tag:lab --expiry 1h
./lab.sh machines | expire NAME | delete NAME | prune
./lab.sh ionscale tailnets get-acl-policy --tailnet lab
./lab.sh restart
./lab.sh down        # -v also forgets all state (keys, CA, database)
```
