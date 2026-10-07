# RFC-7: Production and throughput validation

**Status:** Benchmarks implemented and first results recorded (2026-10-05, below).
The production canary and the UDP-over-TURN figures are still proposed.

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

## Results (2026-10-05)

`crates/mesh/tests/bench.rs`, run as its header says. `bench_harness` is the Go
harness on one machine; `bench_lab` is the mesh lab with `lab.sh netem` delaying
what the peer sends (so the delay is the round trip). One 24-core desktop, 6
seconds or 64 MiB per transfer, one run each: read differences under about 30%
as noise, and the DERP rows at 100 ms as noise altogether.

**What was wrong, and what was changed:**
- **A 64 KiB TCP buffer capped a connection at 64 KiB per round trip**: 3 MiB/s
  at 20 ms, 0.6 MiB/s at 100 ms, on any path. `Limits::tcp_buffer` is now 1 MiB
  by default (`--tcp-buffer`, `tcp_buffer=` in Python, `MeshOptions.tcp_buffer`
  in fakts).
- **The kernel's default UDP buffer (208 KiB) overflowed on downloads** (34,000
  `RcvbufErrors` in one run). `Limits::udp_buffer` asks for 4 MiB, and the loop
  takes up to 64 datagrams before it runs the stack once.
- **Uploads over DERP stalled.** A full DERP queue dropped packets silently, TCP
  sent the window again into the same queue (300,000 drops in 5 s), and the
  relay drops what it cannot pass on at once. Now a full queue holds the
  sockets back, and data frames go out 32 per millisecond
  (`Limits::derp_burst`). `Node::derp_dropped` counts what is still dropped.
- **Congestion control was off.** Cubic is on by default
  (`Limits::congestion`). It made no measurable difference at 20 ms without
  loss; at 100 ms it was the only setting with no stalled upload.
- **The first connection after a start took 5 or 10 s.** A peer does not know a
  node that just joined, and still sends to the UDP port of one that just
  restarted; the handshake was retried only after 5 s. A first handshake is
  now retried after 250 ms, 500 ms, then every second, and a session comes
  back on the UDP port it had (`udp-port` in the state directory).
- **Every `http://` request through the proxy dialed the peer anew** (two round
  trips per request). The proxy keeps its upstream connections, per host.

**Direct path, MiB/s (before -> after):**

| round trip | download, 1 stream | download, 8 | upload, 1 | upload, 8 |
|---|---|---|---|---|
| none (lab) | 108 -> 192 | 139 -> 343 | 191 -> 213 | 185 -> 207 |
| 20 ms | 2.8 -> 10.3 | 17 -> 44 | 3.0 -> 45 | 24 -> 197 |
| 100 ms | 0.6 -> 2.7 | 3.2 -> 13.5 | 0.6 -> 9.3 | 4.8 -> 11.4 (2 of 8 stalled) |
| 100 ms, 1% loss | 0.3 -> 0.7 | 1.8 -> 5.7 | 0.6 -> 9.3 | 4.8 -> 46 |

**DERP only, MiB/s (before -> after):**

| round trip | download, 1 stream | download, 8 | upload, 1 | upload, 8 |
|---|---|---|---|---|
| none (lab) | 60 -> 93 | 105 -> 84 | stalled -> 9.7 | 4.8 (6 of 8 stalled) -> 18 |
| 20 ms | 2.8 -> 4.0 | 8.2 -> 10.2 | 3.0 -> 11.3 | 2.1 (5 stalled) -> 18 |
| 100 ms | 0.6 -> 0.4 | 2.1 -> 0.7 | 0.6 -> 5.5 | 4.3 -> 17.6 |
| 100 ms, 1% loss | 0.2 -> 0.1 | 0.2 -> 0.1 | 0.4 -> 2.9 | 1.3 -> 0.1 (7 of 8 stalled) |

**Through the proxy at 20 ms** (500 small GETs in a row, p50): an `http://`
request 41 ms -> 21 ms (one round trip, as a kept CONNECT tunnel always was).
32 objects of 4 MiB in a row: 2.4 -> 6.5 MiB/s.

**`Session::start` to the first answer, ms:**

| state directory | harness | lab, 20 ms |
|---|---|---|
| empty (joins) | 8 -> 5 | 5154 -> 1880 |
| joined before | 5007 to 10005 -> 6 to 24 | 5084 to 10071 -> 75 |

The 1.9 s left on a first join in the lab is ionskale telling the peer about
the new node; the handshake retries are what find the moment.

**CPU** on a direct path without delay is 4 to 8 CPU-seconds per GiB (about
1.6 Gbit/s on one core's worth): the single task and lock are not the limit on
any link slower than that, so the "performance work" above stays deferred.

**Open:**
- **Loss recovery.** smoltcp has no SACK and a minimum retransmit timeout of
  1 s. That is what is left of the stalls (100 ms, eight streams) and why
  downloads over DERP at 100 ms are slow whatever the buffer; the larger
  buffer makes the eight-stream DERP download at 100 ms somewhat worse (about
  2 -> 0.7 MiB/s). A fix is in the TCP stack, not in a setting.
- **Downloads grow less than uploads** (the peer's sender decides); not looked
  into.
- **CPU per byte rises with delay** (10 to 20 s/GiB at 20 ms against 4 to 8
  without): not explained.
- **`Limits::small()` is unchanged** (no congestion control, pacing or larger
  buffers): nothing here was measured on a board.
- UDP through TURN, and the production canary, as proposed above.

