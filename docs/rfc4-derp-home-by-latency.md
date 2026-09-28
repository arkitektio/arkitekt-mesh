# RFC-4: Pick the home DERP region by measured latency

**Status:** Implemented (September 2026), without the HTTPS fallback.

## Problem

`pick_home` (`driver/node.rs`) takes the lowest region id that has
non-STUN-only nodes. With one region (ionskale's embedded DERP, the lab)
that is right. With a multi-region DERP map (external `derp.sources`, or
Tailscale's public map), a node in Europe can end up homed in a region on
another continent. All DERP traffic then pays that round trip, and peers
reach us through it.

tsnet runs *netcheck*:
- it measures the STUN latency to every region;
- it homes to the fastest, with hysteresis so it does not flap;
- it reports `NetInfo.PreferredDERP` and `DERPLatency` to control.

## Proposal

1. **Netcheck at start and every few minutes:** STUN each region's nodes (the
   code already exists for the home region), and fall back to an HTTPS
   `/derp/latency-check` request where UDP is blocked. Keep the best of three
   samples per region.
2. **Home to the fastest region.** Switch only when another region is 20%
   and at least 10 ms faster, and not within 60 s of the last switch, to
   avoid flapping.
3. **On a switch,** send `NotePreferred` to the new home connection, keep the
   old one until idle, and report `NetInfo { PreferredDERP, DERPLatency }` in
   the `OmitPeers` map update the node already sends.
4. **`Limits::small()` (ESP32):** measure once at start only, and cap the
   number of regions probed.

## Tests

- **Unit:** the selection function over synthetic latency tables, including
  hysteresis, ties and all regions failing.
- **Harness:** a second DERP/STUN region (`RunDERPAndSTUN` twice, a DERP map
  with regions 1 and 2) with delay added on region 1. The node must home to 2,
  and a peer homed on 1 must still be reachable (cross-region DERP).

## Not in scope

Region-aware selection *between* DERP nodes of one region (Tailscale's
`derp.Client` does this). One node per region is the norm for us.

## Done

- `src/netcheck.rs` (sans-IO):
  - STUN probes per region, keeping the best of 3 samples, valid for 15 minutes;
  - `choose` with the hysteresis above: 20% and at least 10 ms faster, and
    60 s after the last switch; the first choice is free;
  - regions marked `Avoid` or `NoMeasureNoHome` are neither measured nor homed to.
- The node:
  - starts on the lowest region (as before), then measures every region at
    once and every `Limits::netcheck_interval` (5 minutes; `small()`: only once);
  - on a switch, connects the new home (`NotePreferred`) and drops the old
    connection, which reconnects as a plain region when next used;
  - reports `PreferredDERP` and `DERPLatency` (`"<id>-v4"`) to control;
  - offers `Node::home_region()`;
  - measures even when DERP-only (`direct: false`).
- Tests:
  - unit tests of selection, hysteresis, unanswered regions and sample expiry;
  - `tests/netcheck.rs`: in the harness's new two-region mode
    (`MESH_HARNESS_TWO_REGIONS`, region 1's STUN answers nothing), the node
    moves to region 2 and still reaches the peer. The `small()` limits are
    tested the same way.

## Not done

- **The HTTPS latency fallback** (`/derp/latency-check`) for networks that
  block UDP. There, nothing is measured and the node keeps the lowest region,
  as before.
- **IPv6 samples**, which come with RFC-2.
