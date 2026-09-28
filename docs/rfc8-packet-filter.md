# RFC-8: Enforce the tailnet's ACLs on the node

**Status:** Implemented (September 2026). ICMPv6, IPv6 extension headers
and `CapGrant` rules are open (see "Not done").

## Problem

Tailscale enforces ACLs at the receiving node: control sends each node a
`PacketFilter` in the map response, and tailscaled drops inbound packets the
filter does not allow. Control only steers who is *in the netmap*.

Our node does no filtering:
- `accept_inbound` (`driver/node.rs`) checks only that a packet comes from
  the peer whose key sent it (cryptokey routing) and is addressed to us.
- The map stream discards `PacketFilter` altogether (`control/stream.rs`
  skips it when parsing, to save memory).

That was harmless while the node only dialed out: smoltcp answered unknown
ports with RST or nothing. Now:
- `Node::listen` accepts inbound TCP;
- `Node::bind_udp` and the TURN relay receive UDP from any peer;
- lok's ACLs are deliberately one-way (`tag:app-n` → `tag:hub-m`, and "the
  hub never initiates", `lok/ionscale/acl.py`), so a node that listens would
  accept connections the tailnet's policy forbids.

## Proposal

1. **Parse `PacketFilter`** (`SrcIPs`, `DstPorts{IP, Ports{First, Last}}`,
   `IPProto`), and the newer `PacketFilters` map, into a compact matcher:
   - prefix sets per rule, with `*` meaning any tailnet address;
   - port ranges;
   - protocols (TCP, UDP, ICMP, SCTP).
   Keep memory small for the ESP32: rules, not an expanded table.
2. **Filter inbound in `deliver`,** after `accept_inbound`:
   - Parse the IP and transport header of each decrypted packet.
   - Allow it if a rule matches (source, destination port, protocol).
   - Otherwise allow it only if it answers a flow we started. A small conntrack
     of outbound 5-tuples with timeouts (TCP until FIN/RST plus a grace
     period, UDP 2 minutes) lets replies to our own dials and TURN allocations
     through without a rule.
3. **Drop everything else,** counting drops (a debug counter, and a trace
   line per new 5-tuple).
4. **With no filter received,** deny inbound except replies, as tailscaled does.
5. **Outbound is not filtered** (Tailscale does not filter it either); the
   peer's own filter decides.

## Tests

- **Unit:** the matcher against Tailscale's filter test vectors (`wgengine/filter`),
  and conntrack expiry.
- **Harness:** testcontrol with an ACL allowing only peer → us on TCP port 80.
  - `Node::listen(80)` accepts from the peer.
  - `listen(81)` never sees a connection: the peer's dial times out.
  - A UDP socket receives replies to its own sends but not unsolicited
    datagrams on a port no rule allows.
- **Lab:** lok's one-way `app → hub` ACL, checked from both ends.

## Done

- `src/filter.rs` (sans-IO, so the ESP32 gets it too):
  - `FilterRule` parsing with `*`, addresses, CIDRs and `a-b` ranges;
  - `apply_update` for `PacketFilter` / `PacketFilters` deltas;
  - `Firewall` with the TCP-SYN, UDP-conntrack and ICMP-echo rules above;
  - a bounded UDP flow table (`Limits::udp_flows`: 1024, `small()` 32).
- The map stream keeps `PacketFilter(s)`. The node applies them at start and
  on every update, checks inbound packets in `deliver` after the cryptokey
  check, and records outbound UDP in `pump`.
- `Node::filtered_packets()` counts drops.
- Tests:
  - unit tests of the matcher, updates, conntrack expiry and bounds;
  - `tests/lab_acl.rs` against ionskale's `lab-acl` tailnet (lok's shape):
    app → hub:80 connects, app → hub:81 and hub → app are dropped by the
    receiving node's filter, UDP replies pass, and unsolicited datagrams do not.
- All other tests pass unchanged: testcontrol and the `lab` tailnet send allow-all.

## Not done

- **IPv6 extension headers** are not followed, so a packet using them needs a
  rule for the extension's protocol number. Rare on tailnets.
- **`CapGrant` rules** (app capabilities, e.g. peer relay grants) are parsed
  away. We act on none of them.
- **With no filter received yet,** the node denies new inbound flows. A
  control server that never sends one (none we know of) would leave a
  listening node unreachable, which is correct but worth knowing.
