//! A node's state and its policy, without I/O: what the tunnel, the paths,
//! the netstack, the netmap, the packet filter and tailnet lock make of
//! every datagram, DERP packet and map response, and when to probe STUN,
//! report endpoints, re-home and talk to which DERP region.
//!
//! A driver feeds it ([`NodeCore::handle_datagram`],
//! [`handle_derp`](NodeCore::handle_derp), [`apply_map`](NodeCore::apply_map),
//! [`rebind`](NodeCore::rebind)), runs it ([`pump`](NodeCore::pump),
//! [`stun`](NodeCore::stun) when due) until [`poll_timeout`](NodeCore::poll_timeout),
//! has the DERP regions they need connected
//! ([`link_derp_for`](NodeCore::link_derp_for)), sends the [`Transmit`]s, and
//! acts on its [`Event`]s: the DERP connections it wants, and what control
//! should hear.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::net::{IpAddr, SocketAddr};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::tcpip::iface::SocketHandle;
use crate::tcpip::socket::tcp::State as TcpState;

use crate::control::netmap::NetMap;
use crate::control::types::{DerpRegion, EndpointType, MapResponse};
use crate::filter::{FilterRule, Firewall};
use crate::keys::{NodePublic, PrivateKey};
use crate::lock::Lock;
use crate::netcheck::Netcheck;
use crate::netstack::{self, Congestion, Netstack};
use crate::paths::{Paths, Transmit, Via};
use crate::time::{Duration, Instant};
use crate::wg::{self, Tunnel};
use crate::{disco, stun};

/// How often to ask STUN for our endpoint (plus up to 6 s of jitter).
pub const STUN_INTERVAL: Duration = Duration::from_secs(20);

/// The home region and every measured region's latency (`<region>-v4`, in
/// seconds), as control's `NetInfo` takes them.
pub type HomeReport = (Option<i32>, BTreeMap<String, f64>);

/// How a node runs: its paths, its buffers, its limits.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// Try direct UDP paths (disco); off means DERP only.
    pub direct: bool,
    /// Direct paths over IPv4 (IPv6 follows from having a v6 socket).
    pub ipv4: bool,
    pub tcp_buffer: usize,
    pub listen_buffer: usize,
    /// How far a TCP receive buffer may grow as its application keeps up
    /// (`fast-tcp` only; 0: it stays as it starts).
    pub tcp_buffer_max: usize,
    pub congestion: Congestion,
    /// Packets held per peer while a handshake is in flight.
    pub handshake_queue: usize,
    /// Peers with WireGuard and path state at once (0: no limit).
    pub max_active_peers: usize,
    /// UDP flows the packet filter remembers replies for.
    pub udp_flows: usize,
    /// How often to measure every region and re-pick the home (`None`: once).
    pub netcheck_interval: Option<Duration>,
}

/// What the driver should do (besides sending [`Transmit`]s).
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Connect to `region` as `info` describes it (replacing a connection
    /// to it made for another description).
    ConnectDerp {
        region: i32,
        info: DerpRegion,
        home: bool,
    },
    /// Close the connection to `region`.
    DropDerp { region: i32 },
    /// Our endpoints changed: tell control.
    Endpoints(Vec<(SocketAddr, EndpointType)>),
    /// The home region (or the first latencies) changed: tell control.
    Home(HomeReport),
}

/// What [`NodeCore::pump`] did.
#[derive(Debug, Default)]
pub struct Pumped {
    pub transmits: Vec<Transmit>,
    /// The sockets were held back: a DERP queue had no room. Pump again
    /// once it drains (and leave the netstack's deadline out until then).
    pub held_back: bool,
}

/// See the module docs.
pub struct NodeCore {
    tunnel: Tunnel,
    paths: Paths,
    netstack: Netstack,
    netmap: NetMap,
    home_region: Option<i32>,
    /// The DERP connections asked for, by region, with the description
    /// each was made for.
    derp: BTreeMap<i32, DerpRegion>,
    /// Sockets the app closed, removed once their close completes.
    closing: Vec<SocketHandle>,
    /// STUN probes in flight and each region's measured latency.
    netcheck: Netcheck,
    stun_endpoint: Option<SocketAddr>,
    /// Our IPv6 address as a STUN server saw it.
    stun_endpoint6: Option<SocketAddr>,
    /// The public address our gateway maps to our UDP port, if any.
    portmap_endpoint: Option<SocketAddr>,
    /// Packets dropped because a DERP connection's queue was full.
    derp_dropped: u64,
    /// The peer (by tailnet address) exempt from eviction.
    priority: Option<IpAddr>,
    /// Our UDP sockets' ports (they change on rebind); no v6 socket, no v6.
    udp_port: u16,
    udp_port6: Option<u16>,
    /// The tailnet's ACLs on inbound packets, by named set as control sends
    /// them, and the firewall compiled from them.
    filter_sets: BTreeMap<String, Vec<FilterRule>>,
    firewall: Firewall,
    /// Tailnet lock: the verified authority, and which peers it hides.
    lock: Lock,
    settings: Settings,
    next_stun: Instant,
    next_netcheck: Option<Instant>,
    /// The endpoints control last heard.
    reported: BTreeSet<SocketAddr>,
    /// Whether control heard any latencies yet.
    latencies_reported: bool,
    events: VecDeque<Event>,
}

impl NodeCore {
    /// A node on `netmap` (its first, with our own node in it), homed to its
    /// lowest region until latencies say otherwise.
    pub fn new(
        node_key: PrivateKey,
        paths: Paths,
        netmap: NetMap,
        filter_sets: BTreeMap<String, Vec<FilterRule>>,
        lock: Lock,
        settings: Settings,
        now: Instant,
    ) -> Self {
        let addresses = netmap.self_addresses().to_vec();
        let mut tunnel = Tunnel::new(node_key);
        tunnel.set_max_queued(settings.handshake_queue);
        let mut netstack = Netstack::new(&addresses, now);
        netstack.set_tcp_buffer(settings.tcp_buffer);
        netstack.set_listen_buffer(settings.listen_buffer);
        netstack.set_tcp_buffer_max(settings.tcp_buffer_max);
        netstack.set_congestion(settings.congestion);
        let mut firewall = Firewall::new(settings.udp_flows);
        firewall.set_filter(crate::filter::compile(&filter_sets));
        let mut node = Self {
            tunnel,
            paths,
            netstack,
            home_region: pick_home(&netmap),
            netmap,
            derp: BTreeMap::new(),
            closing: Vec::new(),
            netcheck: Netcheck::new(),
            stun_endpoint: None,
            stun_endpoint6: None,
            portmap_endpoint: None,
            derp_dropped: 0,
            priority: None,
            udp_port: 0,
            udp_port6: None,
            filter_sets,
            firewall,
            lock,
            settings,
            next_stun: now,
            // Measure every region right away, then every `netcheck_interval`.
            next_netcheck: Some(now),
            reported: BTreeSet::new(),
            latencies_reported: false,
            events: VecDeque::new(),
        };
        node.apply_lock();
        node.sync_peers();
        // Connect the home region right away, so peers can reach us.
        if let Some(home) = node.home_region {
            node.link_derp(home);
        }
        node
    }

    // ------------------------------------------------------------ inputs --

    /// The ports of our UDP sockets (at start, and after a rebind).
    pub fn set_udp_ports(&mut self, port: u16, port6: Option<u16>) {
        self.udp_port = port;
        self.udp_port6 = port6;
    }

    /// A datagram from one of our UDP sockets.
    pub fn handle_datagram(&mut self, now: Instant, src: SocketAddr, data: &[u8]) -> Vec<Transmit> {
        let src = canonical(src);
        if stun::is_stun(data) {
            if let Some((tx, addr)) = stun::parse_response(data) {
                if self.netcheck.answered(&tx, now).is_some() {
                    let addr = canonical(addr);
                    if addr.is_ipv4() {
                        self.stun_endpoint = Some(addr);
                    } else {
                        self.stun_endpoint6 = Some(addr);
                    }
                    self.rehome(now);
                }
            }
            Vec::new()
        } else if disco::looks_like_disco(data) {
            if !self.settings.direct {
                return Vec::new();
            }
            self.paths.on_disco(data, Via::Udp(src), now, &self.netmap)
        } else if wg::is_wireguard(data) {
            self.on_wireguard(data, now)
        } else {
            Vec::new()
        }
    }

    /// A packet `from` a peer, relayed by DERP `region`.
    pub fn handle_derp(
        &mut self,
        now: Instant,
        region: i32,
        from: NodePublic,
        data: &[u8],
    ) -> Vec<Transmit> {
        if disco::looks_like_disco(data) {
            let via = Via::Derp { region, peer: from };
            self.paths.on_disco(data, via, now, &self.netmap)
        } else if wg::is_wireguard(data) {
            self.on_wireguard(data, now)
        } else {
            Vec::new()
        }
    }

    /// A map response from control (tailnet lock already synced).
    pub fn apply_map(&mut self, mut resp: MapResponse) {
        let (whole, named) = (resp.packet_filter.take(), resp.packet_filters.take());
        if crate::filter::apply_update(&mut self.filter_sets, whole, named) {
            let filter = crate::filter::compile(&self.filter_sets);
            self.firewall.set_filter(filter);
        }
        if self.netmap.apply(resp) {
            self.apply_lock();
            self.refresh_derp();
        }
    }

    /// A synced tailnet lock: judge the peers by it.
    pub fn set_lock(&mut self, lock: Lock) {
        self.lock = lock;
        self.apply_lock();
    }

    /// The connection to `region` ended: it is made again when next needed.
    pub fn derp_closed(&mut self, region: i32) {
        self.derp.remove(&region);
    }

    /// The network changed and the driver has new UDP sockets: forget
    /// direct paths and old latencies, reconnect DERP, and rediscover our
    /// endpoints now. WireGuard sessions are kept.
    pub fn rebind(&mut self, now: Instant, port: u16, port6: Option<u16>) {
        self.set_udp_ports(port, port6);
        self.paths.reset_direct();
        for region in core::mem::take(&mut self.derp).into_keys() {
            self.events.push_back(Event::DropDerp { region });
        }
        // A new network: old latencies say nothing about it.
        self.netcheck = Netcheck::new();
        self.stun_endpoint = None;
        self.stun_endpoint6 = None;
        if let Some(home) = self.home_region {
            self.link_derp(home);
        }
        self.next_stun = now;
        self.next_netcheck = Some(now);
        self.reported.clear();
    }

    /// The public address our gateway maps to our UDP port (port mapping).
    pub fn set_portmap_endpoint(&mut self, endpoint: Option<SocketAddr>) {
        self.portmap_endpoint = endpoint;
    }

    /// Never drop this peer's tunnel state for the peer cap.
    pub fn set_priority(&mut self, ip: Option<IpAddr>) {
        self.priority = ip;
    }

    /// A packet for `region`'s DERP connection did not fit its queue.
    pub fn count_derp_dropped(&mut self) {
        self.derp_dropped += 1;
    }

    /// The app closed `socket`: it goes once its close completes.
    pub fn close_socket(&mut self, socket: SocketHandle) {
        self.closing.push(socket);
    }

    // ----------------------------------------------------------- running --

    /// Run the stack and the timers until they are quiet. `room` is what the
    /// fullest connected DERP queue still takes: the stack does not know which
    /// way a packet will go, so this holds back every socket (sending on would
    /// only drop packets and have TCP send them again).
    pub fn pump(&mut self, now: Instant, room: usize) -> Pumped {
        let mut out = Pumped::default();
        let mut room = room;
        for _ in 0..64 {
            let packets = self.netstack.poll(now, room);
            room = room.saturating_sub(packets.len());
            if room == 0 {
                out.held_back = true;
            }
            if packets.is_empty() {
                break;
            }
            for packet in packets {
                let Some(dst) = netstack::destination(&packet) else {
                    continue;
                };
                // Replies to what we send need no rule.
                self.firewall.outbound(&packet, now);
                let Some(peer) = self.netmap.peer_by_ip(dst).map(|p| p.key) else {
                    continue;
                };
                self.tunnel.add_peer(peer);
                if let Ok(sent) = self.tunnel.encapsulate(peer, &packet, now) {
                    out.transmits.extend(self.deliver(sent, now));
                }
            }
        }
        let ticked = self.tunnel.tick(now);
        out.transmits.extend(self.deliver(ticked, now));
        out.transmits.extend(self.paths.tick(now, &self.netmap));
        self.enforce_peer_cap();

        // Sockets the app dropped go once their close completes.
        let netstack = &mut self.netstack;
        self.closing.retain(|&h| {
            let done = matches!(
                netstack.socket(h).state(),
                TcpState::Closed | TcpState::TimeWait
            );
            if done {
                netstack.remove(h);
            }
            !done
        });
        out
    }

    /// Before sending `transmits`: the DERP regions they go to must be
    /// connected (an [`Event::ConnectDerp`] for any that is not).
    pub fn link_derp_for(&mut self, transmits: &[Transmit]) {
        for t in transmits {
            if let Via::Derp { region, .. } = t.via {
                self.link_derp(region);
            }
        }
    }

    /// Whether [`stun`](Self::stun) is due.
    pub fn stun_due(&self, now: Instant) -> bool {
        now >= self.next_stun
    }

    /// When due: the STUN requests to send (every region on a netcheck, else
    /// the home region's for our endpoint), and our endpoints reported if
    /// they changed. `local` and `local6` are this host's addresses on its
    /// default routes, with our ports.
    pub fn stun(
        &mut self,
        now: Instant,
        local: Option<SocketAddr>,
        local6: Option<SocketAddr>,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut requests = Vec::new();
        if now < self.next_stun {
            return requests;
        }
        self.next_stun =
            now + STUN_INTERVAL + Duration::from_millis(u64::from(crate::random::u32() % 6000));
        // Every region when a netcheck is due (DERP-only nodes too: the home
        // region matters to them most), else the home's STUN for our endpoint.
        let all = self.next_netcheck.is_some_and(|at| now >= at);
        if all {
            self.next_netcheck = self.settings.netcheck_interval.map(|every| now + every);
        }
        let direct = self.settings.direct;
        if direct || all {
            let families = (self.settings.ipv4, self.udp_port6.is_some());
            requests = self.stun_requests(now, all, families);
        }
        let mut endpoints: BTreeSet<SocketAddr> = BTreeSet::new();
        if direct && self.settings.ipv4 {
            endpoints.extend(self.stun_endpoint);
            endpoints.extend(local);
        }
        if direct && self.udp_port6.is_some() {
            endpoints.extend(self.stun_endpoint6);
            endpoints.extend(local6);
        }
        let portmapped = self.portmap_endpoint.filter(|_| direct);
        endpoints.extend(portmapped);
        if endpoints != self.reported {
            tracing::debug!("our endpoints: {endpoints:?}");
            self.reported = endpoints.clone();
            let typed: Vec<(SocketAddr, EndpointType)> = endpoints
                .into_iter()
                .map(|e| {
                    let kind = if Some(e) == portmapped {
                        EndpointType::Portmapped
                    } else if e.ip().is_loopback() || is_private(e.ip()) {
                        EndpointType::Local
                    } else {
                        EndpointType::Stun
                    };
                    (e, kind)
                })
                .collect();
            self.paths
                .set_endpoints(typed.iter().map(|(e, _)| *e).collect());
            self.events.push_back(Event::Endpoints(typed));
        }
        requests
    }

    /// After a pass: an endpoint learned meanwhile (a STUN answer, a port
    /// mapping) is reported shortly, not at the next interval.
    pub fn after_pass(&mut self, now: Instant) {
        let unreported = [
            self.stun_endpoint,
            self.stun_endpoint6,
            self.portmap_endpoint,
        ]
        .into_iter()
        .flatten()
        .any(|e| !self.reported.contains(&e));
        if unreported {
            self.next_stun = self.next_stun.min(now + Duration::from_millis(50));
        }
    }

    /// When to run again at the latest. `held_back`: the sockets wait for a
    /// DERP queue, so the stack's own deadline does not count.
    pub fn poll_timeout(&mut self, now: Instant, held_back: bool) -> Instant {
        let mut deadline = self.next_stun;
        for d in [
            self.tunnel.next_deadline(),
            self.paths.next_deadline(now),
            // Held back, the stack always has something to send.
            self.netstack.poll_at(now).filter(|_| !held_back),
        ]
        .into_iter()
        .flatten()
        {
            deadline = deadline.min(d);
        }
        deadline.max(now)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // --------------------------------------------------------- the state --

    pub fn netstack(&self) -> &Netstack {
        &self.netstack
    }

    /// The netstack, for the app's sockets.
    pub fn netstack_mut(&mut self) -> &mut Netstack {
        &mut self.netstack
    }

    pub fn netmap(&self) -> &NetMap {
        &self.netmap
    }

    pub fn tunnel(&self) -> &Tunnel {
        &self.tunnel
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn lock(&self) -> &Lock {
        &self.lock
    }

    /// The DERP region this node is homed to (where peers reach it).
    pub fn home_region(&self) -> Option<i32> {
        self.home_region
    }

    pub fn udp_port(&self) -> u16 {
        self.udp_port
    }

    /// Inbound packets the packet filter has dropped so far.
    pub fn filtered_packets(&self) -> u64 {
        self.firewall.dropped()
    }

    /// Outbound packets dropped so far because a DERP queue was full.
    pub fn derp_dropped(&self) -> u64 {
        self.derp_dropped
    }

    /// The public address our gateway maps to our UDP port, if any.
    pub fn portmap_endpoint(&self) -> Option<SocketAddr> {
        self.portmap_endpoint
    }

    pub fn priority(&self) -> Option<IpAddr> {
        self.priority
    }

    // ----------------------------------------------------------- inside --

    /// Hide the peers tailnet lock does not trust, judge our own key, then
    /// bring the stack and tunnel in line (hidden peers lose their sessions).
    fn apply_lock(&mut self) {
        let lock = &mut self.lock;
        lock.hidden = self.netmap.retain_trusted(|p| lock.trusts(p));
        lock.judge_self(self.netmap.self_node.as_ref());
        let ids: Vec<i64> = self
            .netmap
            .peers()
            .iter()
            .chain(self.netmap.untrusted())
            .map(|p| p.id)
            .collect();
        lock.forget_except(ids.into_iter());
        self.sync_peers();
    }

    /// Bring the stack and the tunnel in line with the netmap. WireGuard and
    /// path state are made when a peer is first used, so only departed
    /// peers are removed here (path state prunes itself on tick).
    fn sync_peers(&mut self) {
        self.netstack.set_addresses(self.netmap.self_addresses());
        let keys: BTreeSet<NodePublic> = self.netmap.peers().iter().map(|p| p.key).collect();
        let stale: Vec<NodePublic> = self
            .tunnel
            .peers()
            .filter(|k| !keys.contains(k))
            .copied()
            .collect();
        for key in stale {
            self.tunnel.remove_peer(&key);
        }
    }

    fn on_wireguard(&mut self, data: &[u8], now: Instant) -> Vec<Transmit> {
        let netmap = &self.netmap;
        let allowed = |key: &NodePublic| netmap.peer_by_key(key).is_some();
        let out = match self.tunnel.decapsulate_allowing(data, now, allowed) {
            Ok(out) => out,
            Err(e) => {
                tracing::trace!("dropped a WireGuard message: {e}");
                return Vec::new();
            }
        };
        self.deliver(out, now)
    }

    /// Route the tunnel's datagrams and feed arrived packets to the stack.
    fn deliver(&mut self, out: wg::Output, now: Instant) -> Vec<Transmit> {
        let mut transmits = Vec::new();
        for (peer, datagram) in out.send {
            transmits.extend(self.paths.route(&peer, datagram, now, &self.netmap));
        }
        for (peer, packet) in out.packets {
            if !accept_inbound(&self.netmap, &peer, &packet) {
                tracing::trace!("dropped a packet from {peer:?} that is not its to send");
            } else if !self.firewall.inbound(&packet, now) {
                tracing::trace!(
                    "the packet filter dropped a packet from {:?}",
                    netstack::source(&packet)
                );
            } else {
                self.netstack.input(packet);
            }
        }
        transmits
    }

    /// Keep at most `max_active_peers` peers' WireGuard and path state,
    /// dropping the least recently used (never the priority peer).
    fn enforce_peer_cap(&mut self) {
        let cap = self.settings.max_active_peers;
        if cap == 0 || self.tunnel.len() <= cap {
            return;
        }
        let protected = self
            .priority
            .and_then(|ip| self.netmap.peer_by_ip(ip))
            .map(|p| p.key);
        let excess = self.tunnel.len() - cap;
        let evict: Vec<NodePublic> = self
            .tunnel
            .least_recently_used()
            .into_iter()
            .filter(|k| Some(*k) != protected)
            .take(excess)
            .collect();
        for key in evict {
            tracing::debug!("over {cap} active peers: dropping {key:?}'s tunnel state");
            self.tunnel.remove_peer(&key);
            self.paths.forget(&key);
        }
    }

    /// STUN requests: to every region (`all`, a netcheck), or to the home
    /// region only (for our endpoint).
    fn stun_requests(
        &mut self,
        now: Instant,
        all: bool,
        (ipv4, ipv6): (bool, bool),
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let home = self.home_region;
        crate::netcheck::targets(&self.netmap.derp_regions)
            .into_iter()
            .filter(|&(region, _)| all || Some(region) == home)
            .filter(|(_, addr)| if addr.is_ipv4() { ipv4 } else { ipv6 })
            .map(|(region, addr)| {
                let mut tx = [0u8; 12];
                crate::random::fill(&mut tx);
                self.netcheck.sent(tx, region, now);
                (addr, stun::request(&tx))
            })
            .collect()
    }

    /// Re-pick the home region from the measured latencies; on a switch,
    /// connect the new home (it announces itself as preferred), drop the
    /// old, and tell control.
    fn rehome(&mut self, now: Instant) {
        let candidates = home_candidates(&self.netmap);
        let latencies: BTreeMap<String, f64> = self
            .netcheck
            .latencies(now)
            .into_iter()
            .map(|(region, d)| (format!("{region}-v4"), d.as_secs_f64()))
            .collect();
        if let Some(new) = self.netcheck.choose(self.home_region, &candidates, now) {
            let old = self.home_region.replace(new);
            tracing::info!(
                "home DERP region {old:?} -> {new} ({:?})",
                self.netcheck.latency(new, now)
            );
            if let Some(old) = old {
                if self.derp.remove(&old).is_some() {
                    self.events.push_back(Event::DropDerp { region: old });
                }
            }
            self.link_derp(new);
            self.latencies_reported = !latencies.is_empty();
            self.events.push_back(Event::Home((Some(new), latencies)));
        } else if !self.latencies_reported && !latencies.is_empty() {
            // The first measurement: report it once even without a switch.
            self.latencies_reported = true;
            self.events
                .push_back(Event::Home((self.home_region, latencies)));
        }
    }

    /// Ask for a connection to `region` unless one made for its current
    /// description is up.
    fn link_derp(&mut self, region: i32) {
        let Some(info) = self.netmap.derp_regions.get(&region).cloned() else {
            return;
        };
        if self.derp.get(&region) == Some(&info) {
            return;
        }
        self.derp.insert(region, info.clone());
        let home = self.home_region == Some(region);
        self.events
            .push_back(Event::ConnectDerp { region, info, home });
    }

    /// After a netmap change: drop DERP connections whose region moved (e.g.
    /// the server restarted on a new port) or went away, and reconnect the
    /// home region right away. Others reconnect when next used.
    fn refresh_derp(&mut self) {
        let stale: Vec<i32> = self
            .derp
            .iter()
            .filter(|(region, info)| self.netmap.derp_regions.get(region) != Some(*info))
            .map(|(region, _)| *region)
            .collect();
        for region in stale {
            tracing::debug!("DERP region {region} changed; reconnecting");
            self.derp.remove(&region);
            self.events.push_back(Event::DropDerp { region });
        }
        if let Some(home) = self.home_region {
            self.link_derp(home);
        }
    }
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is (disco writes
/// IPv4 addresses mapped).
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// The regions a node may home to: not avoided, measurable, with a DERP node.
fn home_candidates(netmap: &NetMap) -> Vec<i32> {
    netmap
        .derp_regions
        .values()
        .filter(|r| !r.avoid && !r.no_measure_no_home && r.nodes.iter().any(|n| !n.stun_only))
        .map(|r| r.region_id)
        .collect()
}

/// The home to start with, before anything is measured: the lowest region.
pub fn pick_home(netmap: &NetMap) -> Option<i32> {
    home_candidates(netmap).into_iter().min()
}

/// Cryptokey routing: a packet from `peer` is accepted only if its source
/// is one of `peer`'s addresses (or allowed IPs) and its destination is ours.
fn accept_inbound(netmap: &NetMap, peer: &NodePublic, packet: &[u8]) -> bool {
    let (Some(src), Some(dst)) = (netstack::source(packet), netstack::destination(packet)) else {
        return false;
    };
    netmap.self_addresses().contains(&dst) && netmap.peer_by_ip(src).is_some_and(|p| p.key == *peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::types::Node as NetNode;
    use crate::keys::PublicKey;

    fn packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p
    }

    #[test]
    fn peers_may_only_send_from_their_own_addresses() {
        let a = NodePublic(PublicKey([1; 32]));
        let b = NodePublic(PublicKey([2; 32]));
        let node = |id, key, ip: &str| {
            crate::control::netmap::Peer::from(NetNode {
                id,
                key,
                addresses: vec![format!("{ip}/32")],
                ..Default::default()
            })
        };
        let mut netmap = NetMap::default();
        netmap.apply(MapResponse {
            node: Some(node(1, NodePublic::default(), "100.64.0.9")),
            peers: vec![node(2, a, "100.64.0.1"), node(3, b, "100.64.0.2")],
            ..Default::default()
        });
        let me = [100, 64, 0, 9];
        assert!(accept_inbound(&netmap, &a, &packet([100, 64, 0, 1], me)));
        // b claiming to be a is dropped.
        assert!(!accept_inbound(&netmap, &b, &packet([100, 64, 0, 1], me)));
        // Not for us, or not from the tailnet at all.
        assert!(!accept_inbound(
            &netmap,
            &a,
            &packet([100, 64, 0, 1], [100, 64, 0, 2])
        ));
        assert!(!accept_inbound(&netmap, &a, &packet([8, 8, 8, 8], me)));
        assert!(!accept_inbound(&netmap, &a, &[0x45, 0]));
    }
}
