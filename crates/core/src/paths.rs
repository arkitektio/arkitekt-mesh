//! Path selection (Tailscale's magicsock, minimally), sans-IO: which way a
//! datagram to a peer goes, direct UDP or a DERP relay, and the disco
//! pings that find and keep a direct path.
//!
//! - Until a direct path is proven, traffic goes via the peer's home DERP
//!   (and to the best UDP address, if any), and every candidate endpoint is
//!   pinged; a CallMeMaybe via DERP asks the peer to ping us back.
//! - A pong over UDP makes its address the best path, trusted for 6.5 s and
//!   renewed by heartbeat pings every 3 s while the peer is in use.
//! - Pings are always answered with a pong on the path they came in on.
//! - Where no direct path comes up and the tailnet has peer relays, a path
//!   through one is set up ([`crate::relay`]) and used like a direct one:
//!   trusted while its pings are answered, left for a direct path as soon
//!   as one is proven. What goes through a relay goes under a Geneve header.
//!
//! State is kept only for peers in use; everything else about a peer is
//! looked up in the [`Directory`] (the netmap) when needed, so a large
//! tailnet costs nothing here until its peers are talked to.

#[allow(unused_imports)]
use crate::prelude::*;
use crate::time::{Duration, Instant};
use alloc::sync::Arc;
use core::net::SocketAddr;
use hashbrown::HashMap;

use crate::disco::{self, DiscoKeys, Message, TxId};
use crate::geneve;
use crate::keys::{DiscoPublic, NodePublic, PrivateKey};
use crate::relay::{self, RelayClient};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
pub const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
pub const SESSION_ACTIVE: Duration = Duration::from_secs(45);
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
pub const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);
/// Path state of a peer unused this long is dropped.
pub const IDLE_FORGET: Duration = Duration::from_secs(300);
/// How often a peer without a direct path is looked for through the peer
/// relays, at most; and how often while it is on one already (which keeps
/// the peer told of the endpoint).
pub const RELAY_DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);
pub const RELAY_UPGRADE_INTERVAL: Duration = Duration::from_secs(60);
/// Pongs answered per peer per second, at most: a flood of (validly sealed)
/// pings must not make us send unbounded traffic.
pub const PONGS_PER_SECOND: u8 = 10;
/// Addresses tried for a peer, at most: its own (the netmap's, its last
/// call-me-maybe's) and those its pings came from.
pub const MAX_CANDIDATES: usize = 32;
/// How much better a path must be to replace one in use, in the points of
/// [`better`]: a tenth faster, or of a better kind.
const SWITCH_MARGIN: i64 = 10;

/// Whether the direct path at `a` is worth leaving the one at `b` for, as
/// tailscale weighs them (`betterAddr`): points for how much faster one is
/// than the other (in percent), and for where it leads: 50 for loopback, 30
/// for link-local, 20 for a private network (a LAN beats the hairpin through
/// the router's public address even a little slower), 10 for IPv6. Unlike
/// tailscale, by a margin: two paths alike do not take turns.
fn better(a: (SocketAddr, Duration), b: (SocketAddr, Duration)) -> bool {
    let percent_faster = |fast: Duration, slow: Duration| -> i64 {
        if slow.is_zero() || fast >= slow {
            return 0;
        }
        100 - (fast.as_micros() * 100 / slow.as_micros()) as i64
    };
    let place = |addr: SocketAddr| -> i64 {
        let ip = addr.ip().to_canonical();
        let kind = match ip {
            _ if ip.is_loopback() => 50,
            core::net::IpAddr::V4(v4) if v4.is_link_local() => 30,
            core::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => 30,
            core::net::IpAddr::V4(v4) if v4.is_private() => 20,
            core::net::IpAddr::V6(v6) if v6.segments()[0] & 0xfe00 == 0xfc00 => 20,
            _ => 0,
        };
        kind + if ip.is_ipv6() { 10 } else { 0 }
    };
    let a_points = percent_faster(a.1, b.1) + place(a.0);
    let b_points = percent_faster(b.1, a.1) + place(b.0);
    a_points > b_points + SWITCH_MARGIN
}

/// Where path selection looks peers up: the netmap.
pub trait Directory {
    fn peer(&self, key: &NodePublic) -> Option<PeerInfo>;
    /// A peer with this disco key (the first, should several share it).
    fn peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo>;
    /// The peer with this disco key if it is the only one. Two nodes can
    /// share a disco key (a cloned machine, two nodes of one process): then
    /// the key alone does not say who sent a message.
    fn only_peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo> {
        self.peer_by_disco(disco)
    }
}

/// Where a datagram goes (or came from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    Udp(SocketAddr),
    /// Through DERP region `region`, to (or from) the peer with this node key.
    Derp {
        region: i32,
        peer: NodePublic,
    },
}

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    pub via: Via,
    pub data: Vec<u8>,
}

/// What we know about a peer, from the netmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    pub home_region: Option<i32>,
    /// Shared with the netmap.
    pub endpoints: Arc<[SocketAddr]>,
    /// Whether its client speaks through peer relays (by its capability
    /// version; one control does not tell is taken to).
    pub relay_capable: bool,
}

/// Where a peer is reached over UDP: its own address, or a relay's with the
/// VNI of the endpoint we both bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Hop {
    addr: SocketAddr,
    vni: Option<u32>,
}

impl Hop {
    fn direct(addr: SocketAddr) -> Self {
        Self { addr, vni: None }
    }

    /// `datagram` (WireGuard or disco) as it goes over this hop.
    fn wrap(&self, protocol: geneve::Protocol, datagram: Vec<u8>) -> Vec<u8> {
        match self.vni {
            Some(vni) => geneve::Header {
                protocol,
                vni,
                control: false,
            }
            .wrap(&datagram),
            None => datagram,
        }
    }
}

struct Peer {
    info: PeerInfo,
    /// Endpoints to try: the netmap's, CallMeMaybe's and ping sources.
    candidates: HashMap<SocketAddr, Option<Instant>>,
    best: Option<(Hop, Duration)>,
    /// The relay `best` goes through (its disco key), if it does.
    relay_server: Option<DiscoPublic>,
    trust_until: Option<Instant>,
    in_flight: HashMap<TxId, (Hop, Instant)>,
    last_relay_discovery: Option<Instant>,
    last_full_ping: Option<Instant>,
    last_heartbeat: Option<Instant>,
    last_send: Option<Instant>,
    /// When anything last happened with this peer (for forgetting it).
    last_used: Instant,
    /// The current one-second pong window: when it began, pongs sent in it.
    pongs: (Instant, u8),
    /// The region this peer last reached us through, if not its home.
    last_derp_region: Option<i32>,
}

impl Peer {
    /// Nothing is allocated until the peer is used: candidates beyond the
    /// netmap's endpoints only appear once pings or CallMeMaybe arrive.
    fn new(info: PeerInfo, now: Instant) -> Self {
        Self {
            last_used: now,
            pongs: (now, 0),
            info,
            candidates: HashMap::new(),
            best: None,
            relay_server: None,
            trust_until: None,
            in_flight: HashMap::new(),
            last_relay_discovery: None,
            last_full_ping: None,
            last_heartbeat: None,
            last_send: None,
            last_derp_region: None,
        }
    }

    fn trusted(&self, now: Instant) -> bool {
        self.best.is_some() && self.trust_until.is_some_and(|t| now < t)
    }

    fn remote(&self) -> relay::Remote {
        relay::Remote {
            node: self.info.node_key,
            disco: self.info.disco_key,
            home_region: self.info.home_region.or(self.last_derp_region),
        }
    }

    /// The relay path this peer is on, if it is on one.
    fn relayed(&self, now: Instant) -> Option<relay::Current> {
        let (hop, _) = self.best?;
        Some(relay::Current {
            server: self.relay_server?,
            vni: hop.vni?,
            trusted: self.trusted(now),
        })
    }

    fn derp(&self) -> Option<Via> {
        let region = self.info.home_region.or(self.last_derp_region)?;
        Some(Via::Derp {
            region,
            peer: self.info.node_key,
        })
    }
}

pub struct Paths {
    disco: DiscoKeys,
    node_key: NodePublic,
    /// Peers in use.
    peers: HashMap<NodePublic, Peer>,
    /// Our own endpoints, sent in CallMeMaybe.
    endpoints: Vec<SocketAddr>,
    /// Whether direct UDP is used at all.
    udp: bool,
    /// No direct paths: peer relays and DERP only (see
    /// [`set_never_direct`](Self::set_never_direct)).
    never_direct: bool,
    /// Paths through peer relays: the servers we may use, and what is under
    /// way with them.
    relay: RelayClient,
}

impl Paths {
    pub fn new(disco: PrivateKey, node_key: NodePublic) -> Self {
        Self {
            relay: RelayClient::new(DiscoPublic(disco.public()), node_key),
            disco: DiscoKeys::new(disco),
            node_key,
            peers: HashMap::new(),
            endpoints: Vec::new(),
            udp: true,
            never_direct: false,
        }
    }

    /// Neither look for direct paths nor answer a peer looking for one: what
    /// is left is the peer relays and DERP. For testing relays where the
    /// peers reach each other, as tailscale's `TS_DEBUG_NEVER_DIRECT_UDP`.
    pub fn set_never_direct(&mut self, never: bool) {
        self.never_direct = never;
    }

    /// The peers we may use as relays (none: peer relays are off).
    pub fn set_relay_servers(&mut self, servers: Vec<relay::Server>) {
        self.relay.set_servers(servers);
    }

    pub fn relay_servers(&self) -> &[relay::Server] {
        self.relay.servers()
    }

    pub fn disco_public(&self) -> DiscoPublic {
        self.disco.public()
    }

    /// Turn direct UDP paths off (DERP only).
    pub fn set_udp(&mut self, enabled: bool) {
        self.udp = enabled;
    }

    pub fn set_endpoints(&mut self, endpoints: Vec<SocketAddr>) {
        self.endpoints = endpoints;
    }

    /// Make sure `info`'s peer has state, current with the directory.
    fn activate(&mut self, info: PeerInfo, now: Instant) -> &mut Peer {
        let key = info.node_key;
        let p = match self.peers.remove(&key) {
            // Same peer, same process: keep what we learned.
            Some(mut p) if p.info.disco_key == info.disco_key => {
                p.info = info;
                p
            }
            // New, or it restarted (new disco key): start over.
            _ => Peer::new(info, now),
        };
        let p = self.peers.entry(key).or_insert(p);
        p.last_used = now;
        p
    }

    /// Forget every direct path (the network changed): traffic falls back
    /// to DERP until pings find paths again.
    pub fn reset_direct(&mut self) {
        self.relay.reset();
        for p in self.peers.values_mut() {
            p.best = None;
            p.relay_server = None;
            p.last_relay_discovery = None;
            p.trust_until = None;
            p.candidates.clear();
            p.in_flight.clear();
            p.last_full_ping = None;
            p.last_heartbeat = None;
        }
    }

    /// Drop `peer`'s path state (it comes back when next used).
    pub fn forget(&mut self, peer: &NodePublic) {
        self.peers.remove(peer);
        self.relay.forget(peer);
    }

    /// How many peers have path state (for tests and diagnostics).
    pub fn active(&self) -> usize {
        self.peers.len()
    }

    /// The current direct address of `peer`, if it is trusted.
    pub fn direct(&self, peer: &NodePublic, now: Instant) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        let (hop, _) = p.best.filter(|_| p.trusted(now))?;
        hop.vni.is_none().then_some(hop.addr)
    }

    /// The relay's address `peer` is reached through, if its trusted path
    /// is one through a peer relay.
    pub fn relayed(&self, peer: &NodePublic, now: Instant) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        let (hop, _) = p.best.filter(|_| p.trusted(now))?;
        hop.vni.map(|_| hop.addr)
    }

    /// Where a datagram to `peer` goes now, as [`route`](Self::route) would
    /// send it: its trusted UDP address (its own, or a peer relay's: see
    /// [`relayed`](Self::relayed)), else its DERP relay. `None` while
    /// the peer is idle: nothing was sent to it within [`SESSION_ACTIVE`], so
    /// no heartbeat keeps a direct path trusted and the next send probes
    /// again. Also `None` with neither a direct address nor a known region.
    pub fn via(&self, peer: &NodePublic, now: Instant) -> Option<Via> {
        let p = self.peers.get(peer)?;
        if p.last_send
            .is_none_or(|t| now.duration_since(t) >= SESSION_ACTIVE)
        {
            return None;
        }
        if self.udp && p.trusted(now) {
            return p.best.map(|b| Via::Udp(b.0.addr));
        }
        p.derp()
    }

    /// Route one datagram to `peer`: the transmits to make, plus any disco
    /// pings the send triggers.
    pub fn route(
        &mut self,
        peer: &NodePublic,
        data: Vec<u8>,
        now: Instant,
        dir: &impl Directory,
    ) -> Vec<Transmit> {
        let mut out = Vec::new();
        let Some(info) = dir.peer(peer) else {
            return out;
        };
        let udp = self.udp;
        let p = self.activate(info, now);
        p.last_send = Some(now);
        if udp && p.trusted(now) {
            let hop = p.best.expect("trusted").0;
            out.push(Transmit {
                via: Via::Udp(hop.addr),
                data: hop.wrap(geneve::Protocol::WireGuard, data),
            });
            return out;
        }
        if let (true, Some((hop, _))) = (udp, p.best) {
            out.push(Transmit {
                via: Via::Udp(hop.addr),
                data: hop.wrap(geneve::Protocol::WireGuard, data.clone()),
            });
        }
        if let Some(derp) = p.derp() {
            out.push(Transmit { via: derp, data });
        }
        let key = *peer;
        self.ping_all(&key, now, true, &mut out);
        out
    }

    /// A disco packet arrived. Returns what to send in response.
    pub fn on_disco(
        &mut self,
        packet: &[u8],
        via: Via,
        now: Instant,
        dir: &impl Directory,
    ) -> Vec<Transmit> {
        let mut out = Vec::new();
        let Some(sender) = disco::sender(packet) else {
            return out;
        };
        // Only a key some peer has gets a box computed.
        if dir.peer_by_disco(&sender).is_none() {
            return out;
        }
        let Some(msg) = self.disco.open(&sender, packet) else {
            return out;
        };
        // Whose message it is. The key alone says so only if one peer has
        // it; else the node DERP got it from, the node a ping names, or, for
        // a pong, the peer whose ping it answers. Each must hold the key.
        let claimed = match (&via, &msg) {
            (Via::Derp { peer, .. }, _) => Some(*peer),
            (_, Message::Ping { node_key, .. }) => *node_key,
            (_, Message::Pong { tx, .. }) => self
                .peers
                .iter()
                .find(|(_, p)| p.info.disco_key == sender && p.in_flight.contains_key(tx))
                .map(|(key, _)| *key),
            _ => None,
        };
        let Some(info) = claimed
            .and_then(|key| dir.peer(&key))
            .filter(|info| info.disco_key == sender)
            .or_else(|| dir.only_peer_by_disco(&sender))
        else {
            return out;
        };
        let node = info.node_key;
        // Pings and CallMeMaybe start a conversation; pongs answer ours.
        if !matches!(msg, Message::Pong { .. }) {
            self.activate(info, now);
        }
        let their_disco = sender;
        if self.never_direct && matches!(via, Via::Udp(_)) {
            return out;
        }
        match msg {
            Message::Ping { tx, .. } => {
                let src = match via {
                    Via::Udp(src) => {
                        if self.udp {
                            if let Some(p) = self.peers.get_mut(&node) {
                                if p.candidates.len() < MAX_CANDIDATES {
                                    p.candidates.entry(src).or_insert(None);
                                }
                            }
                        }
                        src
                    }
                    Via::Derp { region, .. } => {
                        if let Some(p) = self.peers.get_mut(&node) {
                            if p.info.home_region.is_none() {
                                p.last_derp_region = Some(region);
                            }
                        }
                        SocketAddr::from(([127, 3, 3, 40], region as u16))
                    }
                };
                let allowed = self.peers.get_mut(&node).is_some_and(|p| {
                    if now.duration_since(p.pongs.0) >= Duration::from_secs(1) {
                        p.pongs = (now, 0);
                    }
                    p.pongs.1 += 1;
                    p.pongs.1 <= PONGS_PER_SECOND
                });
                if !allowed {
                    return out;
                }
                let pong = self.disco.seal(&their_disco, &Message::Pong { tx, src });
                out.push(Transmit { via, data: pong });
            }
            Message::Pong { tx, .. } => {
                let Some(p) = self.peers.get_mut(&node) else {
                    return out;
                };
                let Some((hop, sent)) = p.in_flight.remove(&tx) else {
                    return out;
                };
                // A pong for a ping sent through a relay comes back through
                // it, not here.
                let addr = hop.addr;
                if hop.vni.is_some() || !matches!(via, Via::Udp(from) if from == addr) {
                    return out;
                }
                let latency = now.duration_since(sent);
                let replace = match p.best {
                    None => true,
                    Some((best, best_latency)) => {
                        best == hop
                            || !p.trusted(now)
                            // A direct path, whatever a relayed one's latency.
                            || best.vni.is_some()
                            || better((addr, latency), (best.addr, best_latency))
                    }
                };
                if replace {
                    if p.best.map(|b| b.0) != Some(hop) {
                        tracing::debug!("direct path to {:?} via {addr} ({latency:?})", node);
                    }
                    p.best = Some((hop, latency));
                    p.relay_server = None;
                }
                if p.best.map(|b| b.0) == Some(hop) {
                    p.trust_until = Some(now + TRUST_UDP_ADDR);
                }
            }
            Message::CallMeMaybe { endpoints } => {
                // Only accepted via DERP, from the peer the disco key belongs to.
                if !matches!(via, Via::Derp { peer, .. } if peer == node) || !self.udp {
                    return out;
                }
                if let Some(p) = self.peers.get_mut(&node) {
                    // What the peer says now is where it is: what an earlier
                    // call-me-maybe or a ping left goes, but for the path in
                    // use (the netmap's own are tried again with these).
                    let keep = p.best.filter(|b| b.0.vni.is_none()).map(|b| b.0.addr);
                    p.candidates.clear();
                    p.candidates.extend(keep.map(|addr| (addr, None)));
                    for ep in endpoints.into_iter().take(MAX_CANDIDATES) {
                        p.candidates.insert(ep, None);
                    }
                }
                self.ping_all(&node, now, false, &mut out);
            }
            Message::CallMeMaybeVia(endpoint) => {
                // As call-me-maybe: over DERP, from the node the key is of.
                if !matches!(via, Via::Derp { peer, .. } if peer == node) || !self.udp {
                    return out;
                }
                let Some(p) = self.peers.get(&node).filter(|p| p.info.relay_capable) else {
                    return out;
                };
                let (remote, current) = (p.remote(), p.relayed(now));
                let mut sends = Vec::new();
                self.relay
                    .on_call_me_maybe_via(&remote, endpoint, current, now, &mut sends);
                self.emit(sends, &mut out);
            }
            Message::RelayAllocated {
                generation,
                endpoint,
            } => {
                // From the relay server (a peer) we asked, over DERP.
                if !matches!(via, Via::Derp { peer, .. } if peer == node) || !self.udp {
                    return out;
                }
                let peers = &self.peers;
                let current = |peer: &NodePublic| peers.get(peer).and_then(|p| p.relayed(now));
                let mut sends = Vec::new();
                self.relay
                    .on_allocated(&node, generation, endpoint, current, now, &mut sends);
                self.emit(sends, &mut out);
            }
            // What a relay server takes: we are none. And a challenge comes
            // under a Geneve header (`on_relayed_disco`), never bare.
            Message::RelayBind(_)
            | Message::RelayChallenge(_)
            | Message::RelayAnswer(_)
            | Message::AllocateRelay { .. } => {}
        }
        out
    }

    /// A disco packet that came under a Geneve header, from `src`: a relay's
    /// own word in the bind handshake (the control bit), or the peer's ping
    /// or pong, forwarded by the relay.
    pub fn on_relayed_disco(
        &mut self,
        packet: &[u8],
        src: SocketAddr,
        header: geneve::Header,
        now: Instant,
        dir: &impl Directory,
    ) -> Vec<Transmit> {
        let mut out = Vec::new();
        let Some(sender) = disco::sender(packet).filter(|_| self.udp) else {
            return out;
        };
        let (vni, mut sends) = (header.vni, Vec::new());
        if header.control {
            // Only a relay we are binding to is listened to, and only its
            // challenge.
            if self.relay.expects(&sender) {
                if let Some(Message::RelayChallenge(challenge)) = self.disco.open(&sender, packet) {
                    self.relay
                        .on_challenge(&sender, src, vni, &challenge, now, &mut sends);
                }
            }
            self.emit(sends, &mut out);
            return out;
        }
        if dir.peer_by_disco(&sender).is_none() {
            return out;
        }
        let hop = Hop {
            addr: src,
            vni: Some(vni),
        };
        let msg = self.disco.open(&sender, packet);
        // Whose it is, as for a bare disco message.
        let claimed = match &msg {
            Some(Message::Ping { node_key, .. }) => *node_key,
            Some(Message::Pong { tx, .. }) => self
                .peers
                .iter()
                .find(|(_, p)| p.info.disco_key == sender && p.in_flight.contains_key(tx))
                .map(|(key, _)| *key),
            _ => None,
        };
        let Some(info) = claimed
            .and_then(|key| dir.peer(&key))
            .filter(|info| info.disco_key == sender)
            .or_else(|| dir.only_peer_by_disco(&sender))
        else {
            return out;
        };
        let node = info.node_key;
        match msg {
            Some(Message::Ping { tx, .. }) => {
                // Answered the way it came, as any ping; and if we are
                // probing this path ourselves, with a ping of our own.
                let p = self.activate(info, now);
                if now.duration_since(p.pongs.0) >= Duration::from_secs(1) {
                    p.pongs = (now, 0);
                }
                p.pongs.1 += 1;
                if p.pongs.1 > PONGS_PER_SECOND {
                    return out;
                }
                let pong = self.disco.seal(&sender, &Message::Pong { tx, src });
                out.push(Transmit {
                    via: Via::Udp(src),
                    data: hop.wrap(geneve::Protocol::Disco, pong),
                });
                self.relay.on_ping(&sender, src, vni, now, &mut sends);
            }
            Some(Message::Pong { tx, .. }) => {
                let Some(p) = self.peers.get_mut(&node) else {
                    return out;
                };
                match p.in_flight.get(&tx) {
                    // A heartbeat on the relay path we are on.
                    Some((sent_to, _)) if *sent_to == hop => {
                        p.in_flight.remove(&tx);
                        if p.best.map(|b| b.0) == Some(hop) {
                            p.trust_until = Some(now + TRUST_UDP_ADDR);
                        }
                    }
                    Some(_) => {}
                    // A handshake's probe: the path works.
                    None => {
                        if let Some(ready) = self.relay.on_pong(&sender, src, vni, &tx, now) {
                            self.adopt(ready, now);
                        }
                    }
                }
            }
            _ => {}
        }
        self.emit(sends, &mut out);
        out
    }

    /// A relay path came up: take it unless a path we trust is in the way.
    fn adopt(&mut self, ready: relay::Ready, now: Instant) {
        let Some(p) = self.peers.get_mut(&ready.peer) else {
            return;
        };
        // On the same relay we must move: it takes our packets from the
        // address we bound from last, and only from there.
        let same_relay = p.relay_server == Some(ready.server);
        if p.trusted(now) && !same_relay {
            return;
        }
        let hop = Hop {
            addr: ready.addr,
            vni: Some(ready.vni),
        };
        tracing::debug!(
            "path to {:?} through the peer relay at {} ({:?})",
            ready.peer,
            ready.addr,
            ready.latency
        );
        p.best = Some((hop, ready.latency));
        p.relay_server = Some(ready.server);
        p.trust_until = Some(now + TRUST_UDP_ADDR);
    }

    /// The relay client's messages, sealed and addressed.
    fn emit(&mut self, sends: Vec<relay::Send>, out: &mut Vec<Transmit>) {
        for send in sends {
            out.push(match send {
                relay::Send::Derp {
                    region,
                    node,
                    disco,
                    msg,
                } => Transmit {
                    via: Via::Derp { region, peer: node },
                    data: self.disco.seal(&disco, &msg),
                },
                relay::Send::Relay {
                    addr,
                    vni,
                    control,
                    disco,
                    msg,
                } => Transmit {
                    via: Via::Udp(addr),
                    data: geneve::Header {
                        protocol: geneve::Protocol::Disco,
                        vni,
                        control,
                    }
                    .wrap(&self.disco.seal(&disco, &msg)),
                },
            });
        }
    }

    /// Heartbeats and ping timeouts.
    pub fn tick(&mut self, now: Instant, dir: &impl Directory) -> Vec<Transmit> {
        let mut out = Vec::new();
        // Forget peers that left the netmap, restarted, or went unused.
        let relay = &mut self.relay;
        self.peers.retain(|key, p| {
            let keep = match dir.peer(key) {
                Some(info) if info.disco_key == p.info.disco_key => {
                    p.info = info;
                    now.duration_since(p.last_used) < IDLE_FORGET
                }
                _ => false,
            };
            if !keep {
                relay.forget(key);
            }
            keep
        });
        let mut sends = Vec::new();
        self.relay.tick(now, &mut sends);
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            let p = self.peers.get_mut(&key).expect("listed");
            p.in_flight.retain(|_, (hop, sent)| {
                let alive = now.duration_since(*sent) < PING_TIMEOUT;
                if !alive
                    && p.best.map(|b| b.0) == Some(*hop)
                    && p.trust_until.is_none_or(|t| now >= t)
                {
                    p.best = None;
                    p.relay_server = None;
                }
                alive
            });
            if !self.udp
                || p.last_send
                    .is_none_or(|t| now.duration_since(t) >= SESSION_ACTIVE)
            {
                continue;
            }
            // No direct path we trust, and relays to ask: look for a path
            // through one, now and then.
            let trusted = p.trusted(now);
            let direct = trusted && p.best.is_some_and(|b| b.0.vni.is_none());
            let since = p.last_relay_discovery.map(|t| now.duration_since(t));
            let due = match since {
                None => true,
                Some(since) if trusted => since >= RELAY_UPGRADE_INTERVAL,
                Some(since) => since >= RELAY_DISCOVERY_INTERVAL,
            };
            if self.relay.has_servers() && p.info.relay_capable && !direct && due {
                p.last_relay_discovery = Some(now);
                let remote = p.remote();
                self.relay.discover(&remote, now, &mut sends);
            }
            if p.last_heartbeat
                .is_some_and(|t| now.duration_since(t) < HEARTBEAT_INTERVAL)
            {
                continue;
            }
            p.last_heartbeat = Some(now);
            let full = !p.trusted(now)
                || p.last_full_ping
                    .is_none_or(|t| now.duration_since(t) >= UPGRADE_INTERVAL);
            if full {
                // The relay path too, if we are on one: it is no candidate
                // of the peer's own.
                if let Some((hop, _)) = p.best.filter(|b| b.0.vni.is_some()) {
                    self.ping(&key, hop, now, &mut out);
                }
                self.ping_all(&key, now, true, &mut out);
            } else if let Some((best, _)) = p.best {
                self.ping(&key, best, now, &mut out);
            }
        }
        self.emit(sends, &mut out);
        out
    }

    /// When [`tick`](Self::tick) next has work, at the latest.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let heartbeat = self
            .peers
            .values()
            .any(|p| {
                p.last_send
                    .is_some_and(|t| now.duration_since(t) < SESSION_ACTIVE)
                    || !p.in_flight.is_empty()
            })
            .then_some(now + HEARTBEAT_INTERVAL);
        [heartbeat, self.relay.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    fn ping(&mut self, key: &NodePublic, hop: Hop, now: Instant, out: &mut Vec<Transmit>) {
        let Some(p) = self.peers.get_mut(key) else {
            return;
        };
        let mut tx = [0u8; 12];
        crate::random::fill(&mut tx);
        p.in_flight.insert(tx, (hop, now));
        if hop.vni.is_none() {
            p.candidates.insert(hop.addr, Some(now));
        }
        let ping = Message::Ping {
            tx,
            node_key: Some(self.node_key),
        };
        let to = p.info.disco_key;
        out.push(Transmit {
            via: Via::Udp(hop.addr),
            data: hop.wrap(geneve::Protocol::Disco, self.disco.seal(&to, &ping)),
        });
    }

    /// Ping every candidate not pinged recently; with `call_me_maybe`, also
    /// ask the peer (via DERP) to ping us.
    fn ping_all(
        &mut self,
        key: &NodePublic,
        now: Instant,
        call_me_maybe: bool,
        out: &mut Vec<Transmit>,
    ) {
        if !self.udp || self.never_direct {
            return;
        }
        let Some(p) = self.peers.get_mut(key) else {
            return;
        };
        for ep in p.info.endpoints.iter() {
            p.candidates.entry(*ep).or_insert(None);
        }
        let due: Vec<SocketAddr> = p
            .candidates
            .iter()
            .filter(|(_, last)| last.is_none_or(|t| now.duration_since(t) >= DISCO_PING_INTERVAL))
            .map(|(addr, _)| *addr)
            .collect();
        if due.is_empty() {
            return;
        }
        p.last_full_ping = Some(now);
        let derp = p.derp();
        let disco_key = p.info.disco_key;
        for addr in due {
            self.ping(key, Hop::direct(addr), now, out);
        }
        if let (true, Some(derp), false) = (call_me_maybe, derp, self.endpoints.is_empty()) {
            let cmm = Message::CallMeMaybe {
                endpoints: self.endpoints.clone(),
            };
            out.push(Transmit {
                via: derp,
                data: self.disco.seal(&disco_key, &cmm),
            });
        }
    }
}

#[cfg(test)]
mod relay_tests;

#[cfg(test)]
mod tests {
    use super::*;

    struct Side {
        paths: Paths,
        node: NodePublic,
        disco: DiscoPublic,
        addr: SocketAddr,
        dir: Dir,
    }

    /// A netmap stand-in.
    #[derive(Default)]
    struct Dir(HashMap<NodePublic, PeerInfo>);

    impl Directory for Dir {
        fn peer(&self, key: &NodePublic) -> Option<PeerInfo> {
            self.0.get(key).cloned()
        }
        fn peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo> {
            self.0.values().find(|p| p.disco_key == *disco).cloned()
        }
        fn only_peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo> {
            let mut with = self.0.values().filter(|p| p.disco_key == *disco);
            let first = with.next()?.clone();
            with.next().is_none().then_some(first)
        }
    }

    /// A LAN address is worth a little latency; a path alike is not worth a
    /// switch; a much faster one is, wherever it leads.
    #[test]
    fn paths_are_weighed_by_latency_and_by_where_they_lead() {
        let ms = Duration::from_millis;
        let at = |addr: &str, latency: u64| (addr.parse::<SocketAddr>().unwrap(), ms(latency));
        let (lan, public) = ("192.168.1.20:41641", "203.0.113.5:41641");
        // The hairpin through the router answers a touch sooner (4 %): the
        // LAN still. A fifth sooner, and the two weigh the same: no switch.
        assert!(better(at(lan, 50), at(public, 48)));
        assert!(!better(at(public, 48), at(lan, 50)));
        assert!(!better(at(lan, 50), at(public, 40)));
        assert!(!better(at(public, 40), at(lan, 50)));
        // Alike, or a few percent apart: no switch either way.
        assert!(!better(at(public, 10), at("198.51.100.9:1", 10)));
        assert!(!better(at(public, 95), at("198.51.100.9:1", 100)));
        assert!(better(at(public, 80), at("198.51.100.9:1", 100)));
        // A LAN path far slower than the public one is not kept for its name.
        assert!(better(at(public, 10), at(lan, 50)));
        // Loopback over a LAN address, link-local over a private one.
        assert!(better(at("127.0.0.1:1", 1), at(lan, 1)));
        assert!(
            !better(at("169.254.1.2:1", 1), at(lan, 1)),
            "ten points apart: no switch"
        );
        // IPv6 alone is not reason enough.
        assert!(!better(at("[2001:db8::1]:1", 10), at(public, 10)));
        assert!(better(at("[fd00::1]:1", 10), at(public, 10)));
    }

    /// Two peers with one disco key: a ping is the one's it names, and the
    /// key alone says nothing.
    #[test]
    fn a_shared_disco_key_does_not_say_who_pinged() {
        let mut me = side("10.0.0.1:1000");
        let twin = side("10.0.0.2:2000");
        introduce(&mut me, &twin, 1);
        // A second node with the first one's disco key, somewhere else.
        let clone = NodePublic(PrivateKey::generate().public());
        let mut info = me.dir.0.get(&twin.node).unwrap().clone();
        info.node_key = clone;
        me.dir.0.insert(clone, info);
        let now = crate::time::now();
        let src: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        let mut theirs = DiscoKeys::new(twin.paths.disco.private.clone());
        let mut ping = |node_key| {
            theirs.seal(
                &me.disco,
                &Message::Ping {
                    tx: [9; 12],
                    node_key,
                },
            )
        };

        // Without a name: dropped, no pong, nobody activated.
        let unnamed = ping(None);
        assert!(me
            .paths
            .on_disco(&unnamed, Via::Udp(src), now, &me.dir)
            .is_empty());
        assert_eq!(me.paths.active(), 0);
        // Naming a node that does not hold the key: dropped too.
        let stranger = NodePublic(PrivateKey::generate().public());
        let misnamed = ping(Some(stranger));
        assert!(me
            .paths
            .on_disco(&misnamed, Via::Udp(src), now, &me.dir)
            .is_empty());
        // Named: answered, and the path state is that node's.
        let named = ping(Some(clone));
        let out = me.paths.on_disco(&named, Via::Udp(src), now, &me.dir);
        assert_eq!(out.len(), 1);
        assert!(me.paths.peers.contains_key(&clone) && !me.paths.peers.contains_key(&twin.node));
        // Over DERP, the node it came from says whose it is.
        let via = Via::Derp {
            region: 1,
            peer: twin.node,
        };
        assert_eq!(me.paths.on_disco(&unnamed, via, now, &me.dir).len(), 1);
        assert!(me.paths.peers.contains_key(&twin.node));
    }

    /// A call-me-maybe says where the peer is now: what earlier ones and
    /// stray pings left is dropped, and no peer can have us try addresses
    /// without end.
    #[test]
    fn candidates_are_the_latest_and_bounded() {
        let mut a = side("10.0.0.1:1000");
        let b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        let now = crate::time::now();
        let via = Via::Derp {
            region: 1,
            peer: b.node,
        };
        let mut theirs = DiscoKeys::new(b.paths.disco.private.clone());
        let mut call =
            |endpoints: Vec<SocketAddr>| theirs.seal(&a.disco, &Message::CallMeMaybe { endpoints });
        let addrs = |range: core::ops::Range<u16>| -> Vec<SocketAddr> {
            range
                .map(|port| SocketAddr::from(([198, 51, 100, 7], port)))
                .collect()
        };
        let first = call(addrs(1..4));
        a.paths.on_disco(&first, via, now, &a.dir);
        let known = |a: &Side| -> usize { a.paths.peers[&b.node].candidates.len() };
        // The three, and the netmap's own (pinged with them).
        assert_eq!(known(&a), 4);
        let second = call(addrs(10..12));
        a.paths.on_disco(&second, via, now, &a.dir);
        assert_eq!(known(&a), 3, "the first three are gone");
        let flood = call(addrs(1000..1500));
        let out = a.paths.on_disco(&flood, via, now, &a.dir);
        assert!(known(&a) <= MAX_CANDIDATES + 1);
        assert!(out.len() <= MAX_CANDIDATES + 1, "{} pings", out.len());
    }

    fn side(addr: &str) -> Side {
        let node = NodePublic(PrivateKey::generate().public());
        let paths = Paths::new(PrivateKey::generate(), node);
        let disco = paths.disco_public();
        Side {
            paths,
            node,
            disco,
            addr: addr.parse().unwrap(),
            dir: Dir::default(),
        }
    }

    fn introduce(a: &mut Side, b: &Side, region: i32) {
        a.paths.set_endpoints(vec![a.addr]);
        a.dir.0.insert(
            b.node,
            PeerInfo {
                node_key: b.node,
                disco_key: b.disco,
                home_region: Some(region),
                endpoints: vec![b.addr].into(),
                relay_capable: true,
            },
        );
    }

    /// Deliver `out` from `from` to `to` (as a network would), returning replies.
    fn deliver(out: Vec<Transmit>, from: &Side, to: &mut Side, now: Instant) -> Vec<Transmit> {
        out.into_iter()
            .filter(|t| disco::looks_like_disco(&t.data))
            .flat_map(|t| {
                let via = match t.via {
                    Via::Udp(_) => Via::Udp(from.addr),
                    Via::Derp { region, .. } => Via::Derp {
                        region,
                        peer: from.node,
                    },
                };
                to.paths.on_disco(&t.data, via, now, &to.dir)
            })
            .collect()
    }

    #[test]
    fn derp_first_then_direct_after_a_pong() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        introduce(&mut b, &a, 1);
        let t0 = crate::time::now();
        assert_eq!(a.paths.via(&b.node, t0), None, "idle before the first send");

        // No path yet: the data goes via DERP, with a ping and a CallMeMaybe.
        let out = a.paths.route(&b.node, b"wg".to_vec(), t0, &a.dir);
        assert!(matches!(
            a.paths.via(&b.node, t0),
            Some(Via::Derp { region: 1, .. })
        ));
        assert!(out
            .iter()
            .any(|t| t.data == b"wg" && matches!(t.via, Via::Derp { region: 1, .. })));
        assert!(out
            .iter()
            .any(|t| t.via == Via::Udp(b.addr) && disco::looks_like_disco(&t.data)));

        // b answers the ping (a pong over UDP) and the CallMeMaybe (pings of its own).
        let replies = deliver(out, &a, &mut b, t0);
        assert!(replies.iter().any(|t| t.via == Via::Udp(a.addr)));
        let back = deliver(replies, &b, &mut a, t0 + Duration::from_millis(3));
        assert_eq!(
            a.paths.direct(&b.node, t0 + Duration::from_millis(3)),
            Some(b.addr)
        );
        assert_eq!(
            a.paths.via(&b.node, t0 + Duration::from_millis(3)),
            Some(Via::Udp(b.addr))
        );

        // Now data goes straight over UDP.
        let out = a.paths.route(
            &b.node,
            b"wg".to_vec(),
            t0 + Duration::from_millis(4),
            &a.dir,
        );
        assert_eq!(
            out,
            vec![Transmit {
                via: Via::Udp(b.addr),
                data: b"wg".to_vec()
            }]
        );

        // b gets a's pong to its own ping and trusts a directly too.
        let _ = deliver(back, &a, &mut b, t0 + Duration::from_millis(5));
        assert_eq!(
            b.paths.direct(&a.node, t0 + Duration::from_millis(5)),
            Some(a.addr)
        );

        // Trust lapses without heartbeats.
        assert_eq!(a.paths.direct(&b.node, t0 + Duration::from_secs(7)), None);
        // And a peer nothing was sent to lately is idle, not relayed.
        let last_send = t0 + Duration::from_millis(4);
        assert_eq!(a.paths.via(&b.node, last_send + SESSION_ACTIVE), None);
    }

    #[test]
    fn derp_pings_get_derp_pongs() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 3);
        introduce(&mut b, &a, 3);
        let ping = disco::seal(
            &a.paths.disco.private,
            &b.disco,
            &Message::Ping {
                tx: [5; 12],
                node_key: Some(a.node),
            },
        );
        let out = b.paths.on_disco(
            &ping,
            Via::Derp {
                region: 3,
                peer: a.node,
            },
            crate::time::now(),
            &b.dir,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].via,
            Via::Derp {
                region: 3,
                peer: a.node
            }
        );
        let (_, pong) = disco::open(&a.paths.disco.private, &out[0].data).unwrap();
        assert_eq!(
            pong,
            Message::Pong {
                tx: [5; 12],
                src: "127.3.3.40:3".parse().unwrap()
            }
        );
    }

    #[test]
    fn derp_only_never_pings() {
        let mut a = side("10.0.0.1:1000");
        let b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        a.paths.set_udp(false);
        let out = a
            .paths
            .route(&b.node, b"wg".to_vec(), crate::time::now(), &a.dir);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].via, Via::Derp { .. }));
    }

    #[test]
    fn heartbeats_are_paced() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        introduce(&mut b, &a, 1);
        let t0 = crate::time::now();
        let out = a.paths.route(&b.node, b"wg".to_vec(), t0, &a.dir);
        let replies = deliver(out, &a, &mut b, t0);
        deliver(replies, &b, &mut a, t0);
        assert!(a.paths.direct(&b.node, t0).is_some());
        let pings = |out: Vec<Transmit>| {
            out.iter()
                .filter(|t| disco::looks_like_disco(&t.data))
                .count()
        };
        let first = pings(a.paths.tick(t0 + Duration::from_millis(10), &a.dir));
        assert_eq!(first, 1, "one heartbeat");
        for ms in [20, 100, 2000] {
            assert_eq!(
                pings(a.paths.tick(t0 + Duration::from_millis(ms), &a.dir)),
                0,
                "at {ms} ms"
            );
        }
        assert_eq!(
            pings(a.paths.tick(t0 + Duration::from_millis(3100), &a.dir)),
            1
        );
    }

    #[test]
    fn pongs_are_rate_limited() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        introduce(&mut b, &a, 1);
        let t0 = crate::time::now();
        let b_disco = b.disco;
        let ping = |tx: u8| {
            disco::seal(
                &a.paths.disco.private,
                &b_disco,
                &Message::Ping {
                    tx: [tx; 12],
                    node_key: Some(a.node),
                },
            )
        };
        let answered = |b: &mut Side, at: Instant, n: u8| {
            (0..n)
                .map(|i| {
                    b.paths
                        .on_disco(&ping(i), Via::Udp(a.addr), at, &b.dir)
                        .len()
                })
                .sum::<usize>()
        };
        assert_eq!(answered(&mut b, t0, 50), PONGS_PER_SECOND as usize);
        // A second later, the budget is back.
        assert_eq!(answered(&mut b, t0 + Duration::from_millis(1001), 3), 3);
    }

    #[test]
    fn strangers_are_ignored() {
        let mut a = side("10.0.0.1:1000");
        let b = side("10.0.0.2:2000");
        let stranger = side("10.0.0.3:3000");
        introduce(&mut a, &b, 1);
        let ping = disco::seal(
            &stranger.paths.disco.private,
            &a.disco,
            &Message::Ping {
                tx: [1; 12],
                node_key: None,
            },
        );
        assert!(a
            .paths
            .on_disco(&ping, Via::Udp(stranger.addr), crate::time::now(), &a.dir)
            .is_empty());
    }
}
