# RFC-10: Paths through peer relays

**Status:** Implemented (November 2026), both sides: our node uses peer
relays and can be one, each tested against tailscale's own code on the
other side. A tailscaled peer takes part with an ionskale that tells
capability versions (its commit 11d808c, November 2026).

## Problem

Two nodes that find no direct path (hard NATs on both sides, UDP let out but
nothing let in) talk through DERP: TCP, through a relay that is where the
DERP map puts it, shared with everyone, and rate-limited. Measured in our
lab: 6.5 MiB/s through a DERP region against 134 MiB/s directly
(docs/rfc7-production-and-throughput.md).

Tailscale's answer (1.86, capability version 120) is the peer relay: a node
of the tailnet with a UDP port open to both forwards their packets. It is
UDP end to end, the relay is a machine the tailnet's admin chose, and it
forwards without being able to read: WireGuard stays end to end.

## How it works

As tailscale's magicsock does it (`relaymanager.go`), in four steps:

1. **Allocate.** Over DERP, a node asks every relay it may use for an
   endpoint for its disco key and the peer's. The answer names the relay's
   addresses, a virtual network id (VNI) and a disco key of the relay's own.
2. **Tell the peer.** The endpoint goes to the peer in a call-me-maybe-via,
   over DERP.
3. **Bind.** Each peer sends the relay a bind message and echoes its
   challenge. The relay then takes that peer's packets from the address the
   answer came from, and from no other.
4. **Probe.** A disco ping to the peer through the relay; its pong makes
   the path usable.

Everything through a relay travels under a Geneve header (RFC 8926, its
fixed eight bytes) with the endpoint's VNI: the bind handshake with the
control bit set, disco and WireGuard without.

Which peers are relays is control's to say, with capability grants in the
packet filter: `tailscale.com/cap/relay` lets a node ask a relay for
endpoints, `tailscale.com/cap/relay-target` (held by the relay towards a
node) is how that node knows it may.

## Done

- `core/src/disco.rs`: the six relay messages, byte for byte tailscale's
  (vectors from its own marshalling, `tests/harness/vectors_test.go`).
- `core/src/geneve.rs`: the header, and how it is told from bare WireGuard,
  disco and STUN on the same socket.
- `core/src/filter.rs`: capability grants (`CapMap`, and the older `Caps`
  list), for the two capabilities above.
- `core/src/relay.rs`: the client, without I/O. Allocation requests are sent
  again after 3 s and given up after 10; a handshake ends after the
  endpoint's bind lifetime, 30 s at most; pings per handshake are ten;
  allocations and handshakes under way are 32 at most, all peers together.
- `core/src/paths.rs`: a peer without a trusted direct path is looked for
  through the relays every 30 s (every 60 s while on one, which keeps the
  peer told). A relay path is used like a direct one: trusted for 6.5 s
  after a pong, kept up by heartbeats, WireGuard through it. A direct path
  replaces it as soon as one is proven.
- `Limits::peer_relay` (on; off for `Limits::small`), `PeerPath::PeerRelay`
  (`kind == "relay"`, `via == "peer relay <address>"` in Python).
- **The relay itself.** `core/src/relay_server.rs`, without I/O: endpoints
  per pair of disco keys, the bind handshake, forwarding by VNI, expiry
  (unbound after 30 s, silent after five minutes), 4096 endpoints at most.
  Its challenge is a MAC over the bind and the address it came from, under a
  secret that changes every two minutes: nothing is kept for a bind, so one
  from a forged address costs a reply and no state. `Node::serve_peer_relay`
  (`driver/peer_relay.rs`) puts it on a UDP port (IPv4 and IPv6) and hands
  endpoints to the peers that ask over DERP and hold
  `tailscale.com/cap/relay` towards us. `Session::serve_peer_relay`,
  `meshd --peer-relay-port`, `Node.relay()` in Python.

Where we do not follow tailscale:

- **A bind and an answer that get no reply are sent again** (every 2 s; the
  bind three times, the answer while the handshake has pings left).
  Tailscale sends each once and waits for the next discovery, 30 s later. A
  test that loses a third of all messages showed one lost datagram costing
  those 30 s.
- **A peer whose capability version control does not tell is taken to speak
  relays.** Tailscale wants version 121 from the netmap. ionskale sends
  none, and our own nodes all do.

## Tests

- `core/src/relay/tests.rs`: the client against a relay server in memory,
  message by message: every refusal, every timeout, and three hundred
  seeded runs of a network that loses a third of its messages, doubles a
  tenth and delivers the rest in any order.
- `core/src/paths/relay_tests.rs`: two nodes' path selection in bytes
  (sealed, under Geneve) with a relay and DERP in memory: the relay
  carrying WireGuard, holding for minutes, giving way to a direct path,
  going away and coming back, a rebind.
- `mesh/tests/peer_relay.rs`: against tailscale 1.102's own code (the Go
  harness, `MESH_HARNESS_RELAY=1`): a tsnet node as the relay, tailscale's
  test control granting its use, a tsnet peer. Our node and the tsnet peer
  through the relay; two of our own nodes through it; peer relays off.
- `fuzz/fuzz_targets/datagrams.rs`: Geneve and the relay messages among
  what a stranger can send.
- `core/src/relay_server/tests.rs`: the relay as a client meets it, sealed
  and under Geneve: who is bound and who is not, the secret's rotation,
  expiry, the table's bound, five thousand datagrams of noise. The
  path-selection tests above run against it too.
- `mesh/tests/peer_relay.rs`, the relay's side: two tsnet nodes that take no
  direct path reach each other through our node's port (`tailscale ping`
  says so); three of our own nodes, one relaying, two carrying a megabyte
  each way through it.

## Setting it up

A node with a UDP port both sides reach is the relay: ours
(`Node::serve_peer_relay`, `meshd --peer-relay-port <port>`), or a tailscaled
with `tailscale set --relay-server-port=<port>`. The tailnet's policy grants
its use. With ionskale, whose app grants are passed on as written, both
directions are spelled out:

```json
"grants": [
  {"src": ["tag:app"], "dst": ["tag:relay"],
   "app": {"tailscale.com/cap/relay": []}},
  {"src": ["tag:relay"], "dst": ["tag:app"],
   "app": {"tailscale.com/cap/relay-target": []}}
]
```

`Limits::never_direct` (tailscale's `TS_DEBUG_NEVER_DIRECT_UDP`) takes the
direct paths away, to see a relay work where the nodes reach each other.

## Not done

- **An ionskale older than its commit 11d808c tells no peer's capability
  version** (`Node.Cap`). Tailscale's own client then takes no peer for
  relay-capable: a tailscaled peer (a hub's sidecar) neither allocates nor
  answers our call-me-maybe-via, and only two of our own nodes meet on a
  relay. From that commit on it keeps the version a machine polls with and
  sends it (its `tests/peer_relay_test.go`: two tailscaled through a third).
  A machine is told of once it has polled again after the upgrade.
- **The relay forwards a datagram at a time, on one task per socket.** No
  batching (`recvmmsg`, GSO) as tailscale's has: its ceiling is unmeasured,
  and lower.
- **A relay does not relay for itself.** Tailscale's node allocates on its
  own relay without the trip through DERP; ours asks only other nodes.
- **No relay, and no use of one, on a board or in the browser**
  (`Limits::small`, the web node): off, unmeasured.
- **The path's MTU is not probed.** The Geneve header adds eight bytes to a
  tunnel packet of at most 1280 + 32: within any Ethernet, not within every
  tunnel under us.
- **`disable-relay-client`** (a node attribute) is not read: the switch is
  `Limits::peer_relay`.
