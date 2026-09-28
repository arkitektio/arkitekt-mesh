# RFC-2: IPv6 underlay (direct paths over IPv6)

**Status:** Implemented (September 2026).

## Problem

The node reaches peers only over IPv4 (the underlay; tailnet addresses
inside the tunnel are unaffected):
- its UDP socket binds `0.0.0.0` (`driver/node.rs`, the socket in
  `start_inner`, `rebind`, and the local-address probe);
- STUN goes only to IPv4 addresses (`stun_requests`: `.filter(|a| a.is_ipv4())`);
- it never reports IPv6 endpoints.

A peer that is only reachable over IPv6 (IPv6-only mobile networks, or
networks with CGNAT on v4 and native v6) is therefore reached through DERP,
even when a direct IPv6 path would work. tsnet uses both families.

## Proposal

1. **Two sockets.** Bind a second UDP socket on `[::]` (IPV6_V6ONLY) next
   to the IPv4 one, on the same port when possible, as magicsock does. Receive
   from both in `run_loop`, and send each datagram on the socket matching the
   destination's family.
2. **Endpoints.**
   - STUN the IPv6 addresses of DERP nodes too, and report the IPv6 reflexive
     address.
   - Also report local global unicast IPv6 addresses, which are often directly
     reachable with no NAT.
3. **Paths.**
   - `paths.rs` already carries `SocketAddr`s: ping IPv6 candidates like IPv4
     ones.
   - Keep disco's rule (prefer the lower latency, switch only on a 10% gain)
     and add a small bias toward IPv4 on ties, as Tailscale does.
4. **DERP over IPv6** where a node has only an IPv6 address (`DerpNode.ipv6`).
5. **No IPv6 support at all.** If `[::]` cannot be bound (IPv6 disabled),
   run IPv4-only, as today.
6. **ESP32.** Behind a cargo feature or a runtime switch: lwIP IPv6 costs RAM.

## Tests

- **Harness:**
  - `MESH_HARNESS_ADDR=::1` makes the control server, DERP and the tsnet peer
    IPv6-only. The node must find a direct path (`direct_path` returns an IPv6
    `SocketAddr`).
  - A dual-stack peer is reached over IPv4 when the IPv6 latency is equal.
- **Unit:** endpoint collection includes global IPv6 addresses and drops
  link-local ones.

## Not in scope

The IPv6 tailnet addresses (`fd7a:…`) already work inside the tunnel. This
RFC is about the network underneath.

## Done

- A second UDP socket on `[::]` (IPv6-only via `socket2`, so it does not
  claim IPv4 ports).
  - Datagrams from both sockets go through the same handling.
  - Each send leaves on the socket of its destination's family.
  - IPv4-mapped addresses (as disco writes them) are made canonical first.
- STUN goes to every DERP node's IPv4 and IPv6 addresses
  (`DerpNode::stun_addrs`). The reflexive address is kept per family
  (`stun_endpoint`, `stun_endpoint6`).
- The node reports the IPv6 STUN endpoint, plus its global IPv6 address on
  the default route. Loopback, link-local and unique-local addresses (which
  include tailnet `fd7a:` addresses) are left out.
- Paths needed no change: they carry `SocketAddr`s, and disco's rule (switch
  only for a clearly faster path) keeps the first trusted path.
- `Limits::ipv4` / `Limits::ipv6` choose the families. The default is both;
  `small()` turns IPv6 off for the ESP32 (lwIP IPv6 costs RAM). Where `[::]`
  cannot be bound, the node runs over IPv4 alone.
- `rebind` rebinds both sockets.
- Tests (`tests/ipv6.rs`) use the harness's new IPv6 mode
  (`MESH_HARNESS_ADDR=::1`):
  - DERP moves to the node's `IPv6` field, as Go's client requires;
  - the harness answers STUN over IPv6, since tailscale's test STUN server
    is IPv4-only;
  - a node with `ipv4: false` gets a direct IPv6 path to the tsnet peer;
  - with both families off it stays on DERP.
  - The ESP32 firmware still builds.

## Not done

- **No bias toward IPv4 on equal latency.** The first trusted path wins.
- **DERP over IPv6** is used when a node has only an IPv6 address (it already
  was). There is no Happy-Eyeballs race between the two families.
- **No real dual-stack network.** This machine has no global IPv6, so only
  `::1` is tested; a real dual-stack network is part of RFC-7's production
  run.
