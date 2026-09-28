# RFC-7: Production and throughput validation

**Status:** Proposed.

## Problem

The node is tested hermetically (the Go harness) and against our ionskale
fork locally (the mesh lab, including the ESP32 and LiveKit over TURN). Two
things are unknown:
1. **The production control server** (`ionscale.arkitekt.live`). It uses
   public certificates, lok-minted keys that expire after 15 minutes
   (`tag:app-*`, `tag:hub-*`), real ACLs, and nodes spread over the internet
   with real NATs. No run of our client there is recorded.
2. **Throughput.** `run_loop` owns all state behind one `Mutex<State>`
   (tunnel, paths, netstack). smoltcp and the userspace WireGuard run on one
   task. A 1 MiB echo and a small video stream pass, but no bandwidth or CPU
   figure exists. Microscopy data (zarr chunks over S3 through the proxy) and
   LiveKit video at production bitrates will find the ceiling.

## Proposal

**Production canary** (against a staging tailnet, never user tailnets):
- A `mesh-ci` organization on the next deployment, with a service token for
  CI that mints ephemeral `tag:ci-*` keys per run.
- A nightly job runs `tests/lab.rs` pointed at it: `ARKITEKT_TEST_MESH_URL`
  set to production, no `ARKITEKT_MESH_CA_FILE` (public roots), and a
  permanent test hub as the peer.
- Afterwards, `reconcile_meshes --revoke-orphans`.

**Benchmarks,** in `crates/mesh/benches` or as a lab test with `--ignored`:
- TCP through `Node::dial` against the peer's echo: MB/s, and CPU per MB.
- UDP through TURN: loss and jitter at 5, 20 and 50 Mbit/s.
- The HTTP proxy: parallel S3-style GETs of 4 MiB objects.
- Record the numbers in this RFC, and re-run them when `node.rs` changes.

**Performance work,** only once the numbers point at it:
- Move WireGuard crypto off the state lock (encrypt and decrypt per peer
  outside it).
- Batch netstack polling.
- Use GSO/GRO on Linux for the UDP socket.

## Targets (first guess, to be revised)

- **TCP over a direct LAN path:** at least 200 Mbit/s on a desktop.
- **LiveKit 1080p30 (about 5 Mbit/s) over TURN:** under 1% loss.
- **ESP32 over DERP:** at least 100 KB/s at `Limits::small()`, with the heap
  floor above 30 KiB (it is 34 KiB today with TLS verification).
