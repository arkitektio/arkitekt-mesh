# RFC-3: NAT port mapping (UPnP IGD, NAT-PMP, PCP)

**Status:** Implemented for PCP and NAT-PMP (September 2026). UPnP IGD is
not done.

## Problem

Behind a NAT, the node offers peers its STUN-discovered reflexive address
and its local addresses. With endpoint-dependent NAT on both sides,
hole-punching fails and traffic stays on DERP. tsnet's portmapper asks the
router for a port mapping (UPnP IGD, NAT-PMP or PCP), which gives a stable
public `ip:port` that works even then. Home and lab routers commonly offer
one of the three. We implement none, so more of our traffic relays through
DERP than tsnet's would, adding latency and loading the DERP server.

## Proposal

A `portmap` module in the tokio driver, behind a cargo feature (default on
for desktops and servers, off for the ESP32):
1. **Discover the gateway:** the default route on Linux, macOS and Windows.
2. **Try PCP, then NAT-PMP** (both small UDP protocols, RFC 6887/6886),
   **then UPnP IGD** (SSDP discovery plus SOAP `AddPortMapping`). The UPnP
   part can use `igd-next`; PCP and NAT-PMP are small enough to write, as
   with STUN.
3. **Map the node's UDP port** (both families, with RFC-2) for 2 hours, and
   renew at half the lifetime.
4. **Report the mapped `ip:port`** as an endpoint of type `Portmapped`
   (`EndpointType` exists in `control/types.rs`), and drop it when the
   mapping lapses.
5. **Delete the mapping on shutdown** (best effort).

## Tests

- **Unit:** encode and decode PCP and NAT-PMP against RFC test vectors and
  captured packets from Tailscale's own portmapper tests.
- **Lab:** add a `miniupnpd` container on a NATed Docker network with the
  test node behind it. The mapped endpoint must be reported, and a peer
  outside must reach the node directly with no DERP (`direct_path` is `Some`).

## Risks

- Routers disagree with the specs. Keep each protocol behind a timeout
  (about 250 ms) and cache which one works per gateway.
- On shared networks, mappings are visible to anyone on the LAN. Map only
  the WireGuard UDP port, which already authenticates everything.

## Done

- **Codecs** (`src/portmap.rs`, sans-IO):
  - NAT-PMP external-address and UDP map requests and responses (RFC 6886);
  - PCP `MAP` requests and responses with nonce checking (RFC 6887);
  - the Linux default gateway from `/proc/net/route`.
  - Unit tests follow the RFC layouts, including refusals and mismatched
    answers (another port, another nonce).
- **Driver** (`driver/portmap.rs`), behind feature `portmap` (on by default)
  and `Limits::portmap` (off in `small()`, and when `direct` is off):
  - It is a task of its own, with its own socket, so nothing on the hot path
    waits for a gateway. Each attempt waits 250 ms, then 500 ms.
  - It tries PCP first, then NAT-PMP, and keeps using whichever worked.
  - It asks for 7200 s and renews at half the granted lifetime.
  - It maps again when the node's port changes (rebind), deleting the old
    mapping.
  - It logs an epoch that goes backwards (the gateway restarted), and the
    renewal maps again.
  - It deletes the mapping (lifetime 0, best effort) when the node stops.
  - After failures it backs off from 1 up to 10 minutes.
  - The mapped address is reported to control as a `Portmapped` endpoint
    (`EndpointType` 3), and endpoints now carry their type explicitly.
- **Tests** (`tests/portmap_pcp.rs`, `tests/portmap_natpmp.rs`, Linux) use a
  fake NAT gateway (`tests/fake_nat`). For each mapping it binds a real
  "external" socket on 127.0.0.2 and forwards both ways to the node's port.
  With 2 s mappings, the tests check that:
  - the other node sees the mapped address among A's endpoints;
  - its disco traffic comes in through the NAT;
  - the mapping is renewed;
  - after a gateway reboot, a new port is mapped and reported;
  - a delete arrives when A stops.
  - Test-only override: `ARKITEKT_MESH_PORTMAP_GATEWAY=ip:port`.

## Not done

- **UPnP IGD** (SSDP, SOAP). Many consumer routers speak only this. It needs
  multicast and a real NAT to test, which the Docker lab does not have yet.
- **Gateway discovery on macOS and Windows** (tracked in RFC-6). There,
  port mapping only runs with the override.
- **IPv6** (PCP can map it, but IPv6 rarely needs NAT traversal).
- **Unsolicited NAT-PMP announcements** (multicast on port 5350). A gateway
  restart is noticed at the next renewal instead.
