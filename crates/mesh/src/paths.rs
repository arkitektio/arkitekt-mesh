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
//!
//! State is kept only for peers in use; everything else about a peer is
//! looked up in the [`Directory`] (the netmap) when needed, so a large
//! tailnet costs nothing here until its peers are talked to.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::disco::{self, Message, TxId};
use crate::keys::{DiscoPublic, NodePublic, PrivateKey};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
pub const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
pub const SESSION_ACTIVE: Duration = Duration::from_secs(45);
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
pub const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);
/// Path state of a peer unused this long is dropped.
pub const IDLE_FORGET: Duration = Duration::from_secs(300);
/// Pongs answered per peer per second, at most: a flood of (validly sealed)
/// pings must not make us send unbounded traffic.
pub const PONGS_PER_SECOND: u8 = 10;

/// Where path selection looks peers up: the netmap.
pub trait Directory {
    fn peer(&self, key: &NodePublic) -> Option<PeerInfo>;
    fn peer_by_disco(&self, disco: &DiscoPublic) -> Option<PeerInfo>;
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
}

struct Peer {
    info: PeerInfo,
    /// Endpoints to try: the netmap's, CallMeMaybe's and ping sources.
    candidates: HashMap<SocketAddr, Option<Instant>>,
    best: Option<(SocketAddr, Duration)>,
    trust_until: Option<Instant>,
    in_flight: HashMap<TxId, (SocketAddr, Instant)>,
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
            trust_until: None,
            in_flight: HashMap::new(),
            last_full_ping: None,
            last_heartbeat: None,
            last_send: None,
            last_derp_region: None,
        }
    }

    fn trusted(&self, now: Instant) -> bool {
        self.best.is_some() && self.trust_until.is_some_and(|t| now < t)
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
    disco: PrivateKey,
    node_key: NodePublic,
    /// Peers in use.
    peers: HashMap<NodePublic, Peer>,
    /// Our own endpoints, sent in CallMeMaybe.
    endpoints: Vec<SocketAddr>,
    /// Whether direct UDP is used at all.
    udp: bool,
}

impl Paths {
    pub fn new(disco: PrivateKey, node_key: NodePublic) -> Self {
        Self {
            disco,
            node_key,
            peers: HashMap::new(),
            endpoints: Vec::new(),
            udp: true,
        }
    }

    pub fn disco_public(&self) -> DiscoPublic {
        DiscoPublic(self.disco.public())
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
        for p in self.peers.values_mut() {
            p.best = None;
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
    }

    /// How many peers have path state (for tests and diagnostics).
    pub fn active(&self) -> usize {
        self.peers.len()
    }

    /// The current direct address of `peer`, if it is trusted.
    pub fn direct(&self, peer: &NodePublic, now: Instant) -> Option<SocketAddr> {
        let p = self.peers.get(peer)?;
        p.trusted(now).then(|| p.best.map(|b| b.0)).flatten()
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
            out.push(Transmit {
                via: Via::Udp(p.best.expect("trusted").0),
                data,
            });
            return out;
        }
        if let (true, Some((addr, _))) = (udp, p.best) {
            out.push(Transmit {
                via: Via::Udp(addr),
                data: data.clone(),
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
        let Some(info) = dir.peer_by_disco(&sender) else {
            return out;
        };
        let node = info.node_key;
        let Some((_, msg)) = disco::open(&self.disco, packet) else {
            return out;
        };
        // Pings and CallMeMaybe start a conversation; pongs answer ours.
        if !matches!(msg, Message::Pong { .. }) {
            self.activate(info, now);
        }
        let their_disco = sender;
        match msg {
            Message::Ping { tx, .. } => {
                let src = match via {
                    Via::Udp(src) => {
                        if self.udp {
                            if let Some(p) = self.peers.get_mut(&node) {
                                p.candidates.entry(src).or_insert(None);
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
                let pong = disco::seal(&self.disco, &their_disco, &Message::Pong { tx, src });
                out.push(Transmit { via, data: pong });
            }
            Message::Pong { tx, .. } => {
                let Some(p) = self.peers.get_mut(&node) else {
                    return out;
                };
                let Some((addr, sent)) = p.in_flight.remove(&tx) else {
                    return out;
                };
                if !matches!(via, Via::Udp(from) if from == addr) {
                    return out;
                }
                let latency = now.duration_since(sent);
                let better = match p.best {
                    None => true,
                    Some((best, best_latency)) => {
                        best == addr || !p.trusted(now) || latency < best_latency.mul_f64(0.9)
                    }
                };
                if better {
                    if p.best.map(|b| b.0) != Some(addr) {
                        tracing::debug!("direct path to {:?} via {addr} ({latency:?})", node);
                    }
                    p.best = Some((addr, latency));
                }
                if p.best.map(|b| b.0) == Some(addr) {
                    p.trust_until = Some(now + TRUST_UDP_ADDR);
                }
            }
            Message::CallMeMaybe { endpoints } => {
                // Only accepted via DERP, from the peer the disco key belongs to.
                if !matches!(via, Via::Derp { peer, .. } if peer == node) || !self.udp {
                    return out;
                }
                if let Some(p) = self.peers.get_mut(&node) {
                    for ep in endpoints {
                        p.candidates.insert(ep, None);
                    }
                    for last in p.candidates.values_mut() {
                        *last = None;
                    }
                }
                self.ping_all(&node, now, false, &mut out);
            }
        }
        out
    }

    /// Heartbeats and ping timeouts.
    pub fn tick(&mut self, now: Instant, dir: &impl Directory) -> Vec<Transmit> {
        let mut out = Vec::new();
        // Forget peers that left the netmap, restarted, or went unused.
        self.peers.retain(|key, p| match dir.peer(key) {
            Some(info) if info.disco_key == p.info.disco_key => {
                p.info = info;
                now.duration_since(p.last_used) < IDLE_FORGET
            }
            _ => false,
        });
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            let p = self.peers.get_mut(&key).expect("listed");
            p.in_flight.retain(|_, (addr, sent)| {
                let alive = now.duration_since(*sent) < PING_TIMEOUT;
                if !alive
                    && p.best.map(|b| b.0) == Some(*addr)
                    && p.trust_until.is_none_or(|t| now >= t)
                {
                    p.best = None;
                }
                alive
            });
            if !self.udp
                || p.last_send
                    .is_none_or(|t| now.duration_since(t) >= SESSION_ACTIVE)
            {
                continue;
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
                self.ping_all(&key, now, true, &mut out);
            } else if let Some((best, _)) = p.best {
                self.ping(&key, best, now, &mut out);
            }
        }
        out
    }

    /// When [`tick`](Self::tick) next has work, at the latest.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.peers
            .values()
            .any(|p| {
                p.last_send
                    .is_some_and(|t| now.duration_since(t) < SESSION_ACTIVE)
                    || !p.in_flight.is_empty()
            })
            .then_some(now + HEARTBEAT_INTERVAL)
    }

    fn ping(&mut self, key: &NodePublic, addr: SocketAddr, now: Instant, out: &mut Vec<Transmit>) {
        let Some(p) = self.peers.get_mut(key) else {
            return;
        };
        let mut tx = [0u8; 12];
        OsRng.fill_bytes(&mut tx);
        p.in_flight.insert(tx, (addr, now));
        p.candidates.insert(addr, Some(now));
        let ping = Message::Ping {
            tx,
            node_key: Some(self.node_key),
        };
        out.push(Transmit {
            via: Via::Udp(addr),
            data: disco::seal(&self.disco, &p.info.disco_key, &ping),
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
        if !self.udp {
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
            self.ping(key, addr, now, out);
        }
        if let (true, Some(derp), false) = (call_me_maybe, derp, self.endpoints.is_empty()) {
            let cmm = Message::CallMeMaybe {
                endpoints: self.endpoints.clone(),
            };
            out.push(Transmit {
                via: derp,
                data: disco::seal(&self.disco, &disco_key, &cmm),
            });
        }
    }
}

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
        let t0 = Instant::now();

        // No path yet: the data goes via DERP, with a ping and a CallMeMaybe.
        let out = a.paths.route(&b.node, b"wg".to_vec(), t0, &a.dir);
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
    }

    #[test]
    fn derp_pings_get_derp_pongs() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 3);
        introduce(&mut b, &a, 3);
        let ping = disco::seal(
            &a.paths.disco,
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
            Instant::now(),
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
        let (_, pong) = disco::open(&a.paths.disco, &out[0].data).unwrap();
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
            .route(&b.node, b"wg".to_vec(), Instant::now(), &a.dir);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].via, Via::Derp { .. }));
    }

    #[test]
    fn heartbeats_are_paced() {
        let mut a = side("10.0.0.1:1000");
        let mut b = side("10.0.0.2:2000");
        introduce(&mut a, &b, 1);
        introduce(&mut b, &a, 1);
        let t0 = Instant::now();
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
        let t0 = Instant::now();
        let b_disco = b.disco;
        let ping = |tx: u8| {
            disco::seal(
                &a.paths.disco,
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
            &stranger.paths.disco,
            &a.disco,
            &Message::Ping {
                tx: [1; 12],
                node_key: None,
            },
        );
        assert!(a
            .paths
            .on_disco(&ping, Via::Udp(stranger.addr), Instant::now(), &a.dir)
            .is_empty());
    }
}
