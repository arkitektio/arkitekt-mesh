//! Path selection with a peer relay, in bytes: two nodes that cannot reach
//! each other directly, a DERP region that carries anything slowly, and a
//! relay server as tailscale's `net/udprelay` behaves, all in memory. What
//! the nodes put on the wire is what is carried, sealed and under its
//! Geneve header.

use super::*;
use crate::disco::{RelayBind, RelayEndpoint};
use alloc::collections::VecDeque;

const REGION: i32 = 3;
const RELAY_ADDR: &str = "198.51.100.1:40000";

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

struct Side {
    paths: Paths,
    node: NodePublic,
    disco: DiscoPublic,
    addr: SocketAddr,
    dir: Dir,
    /// WireGuard datagrams that arrived, and how: `"derp"`, `"relay"`, `"direct"`.
    got: Vec<(&'static str, Vec<u8>)>,
}

fn side(addr: &str) -> Side {
    let node = NodePublic(PrivateKey::generate().public());
    let paths = Paths::new(PrivateKey::generate(), node);
    Side {
        disco: paths.disco_public(),
        paths,
        node,
        addr: addr.parse().unwrap(),
        dir: Dir::default(),
        got: Vec::new(),
    }
}

/// One endpoint of the relay.
struct Endpoint {
    vni: u32,
    clients: [DiscoPublic; 2],
    lamport_id: u64,
    bound: [Option<SocketAddr>; 2],
}

/// The relay: a node of the tailnet (allocations come to its node's disco
/// key over DERP) with a UDP port of its own and a disco key for binding.
struct Relay {
    node: NodePublic,
    node_disco: PrivateKey,
    bind_disco: PrivateKey,
    addr: SocketAddr,
    endpoints: Vec<Endpoint>,
    lamport: u64,
    /// Packets forwarded, for the tests to count.
    forwarded: usize,
}

impl Relay {
    fn new() -> Self {
        Self {
            node: NodePublic(PrivateKey::generate().public()),
            node_disco: PrivateKey::generate(),
            bind_disco: PrivateKey::generate(),
            addr: RELAY_ADDR.parse().unwrap(),
            endpoints: Vec::new(),
            lamport: 0,
            forwarded: 0,
        }
    }

    fn server(&self) -> relay::Server {
        relay::Server {
            node: self.node,
            disco: DiscoPublic(self.node_disco.public()),
            home_region: Some(REGION),
        }
    }

    fn info(&self) -> PeerInfo {
        PeerInfo {
            node_key: self.node,
            disco_key: DiscoPublic(self.node_disco.public()),
            home_region: Some(REGION),
            endpoints: vec![].into(),
            relay_capable: true,
        }
    }

    fn challenge(src: SocketAddr) -> [u8; 32] {
        let mut out = [0xc3; 32];
        out[..2].copy_from_slice(&src.port().to_be_bytes());
        out
    }

    /// An allocation request over DERP: the answer, for its sender.
    fn on_derp(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let (from, msg) = disco::open(&self.node_disco, packet)?;
        let Message::AllocateRelay {
            clients,
            generation,
        } = msg
        else {
            return None;
        };
        if !clients.contains(&from) {
            return None;
        }
        let at = match self.endpoints.iter().position(|e| e.clients == clients) {
            Some(at) => at,
            None => {
                self.lamport += 1;
                self.endpoints.push(Endpoint {
                    vni: 0x1000 + self.lamport as u32,
                    clients,
                    lamport_id: self.lamport,
                    bound: [None, None],
                });
                self.endpoints.len() - 1
            }
        };
        let e = &self.endpoints[at];
        let endpoint = RelayEndpoint {
            server: DiscoPublic(self.bind_disco.public()),
            clients: e.clients,
            lamport_id: e.lamport_id,
            vni: e.vni,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            addrs: vec![self.addr],
        };
        Some(disco::seal(
            &self.node_disco,
            &from,
            &Message::RelayAllocated {
                generation,
                endpoint,
            },
        ))
    }

    /// A datagram on its port: an answer for `src`, or the datagram
    /// forwarded as it is to the other client.
    fn on_udp(&mut self, src: SocketAddr, datagram: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
        let (header, payload) = geneve::unwrap(datagram)?;
        let e = self.endpoints.iter_mut().find(|e| e.vni == header.vni)?;
        if !header.control {
            let from = e.bound.iter().position(|b| *b == Some(src))?;
            let to = e.bound[1 - from]?;
            self.forwarded += 1;
            return Some((to, datagram.to_vec()));
        }
        let (sender, msg) = disco::open(&self.bind_disco, payload)?;
        let index = e.clients.iter().position(|c| *c == sender)?;
        let other = e.clients[1 - index];
        match msg {
            Message::RelayBind(bind)
                if bind.vni == e.vni && bind.remote == other && bind.generation != 0 =>
            {
                let challenge = Message::RelayChallenge(RelayBind {
                    challenge: Self::challenge(src),
                    ..bind
                });
                let sealed = disco::seal(&self.bind_disco, &sender, &challenge);
                Some((
                    src,
                    geneve::Header {
                        control: true,
                        ..header
                    }
                    .wrap(&sealed),
                ))
            }
            Message::RelayAnswer(answer)
                if answer.vni == e.vni
                    && answer.remote == other
                    && answer.challenge == Self::challenge(src) =>
            {
                e.bound[index] = Some(src);
                None
            }
            _ => None,
        }
    }
}

/// How the network between the three is.
#[derive(Clone, Copy)]
struct Net {
    /// The two nodes reach each other's addresses.
    direct: bool,
    /// The relay's port answers.
    relay: bool,
}

struct World {
    nodes: [Side; 2],
    relay: Relay,
    net: Net,
    now: Instant,
    wire: VecDeque<(usize, Transmit)>,
    /// Every datagram a node sent to the relay's address.
    to_relay: usize,
}

/// A WireGuard transport message carrying `tag`.
fn wireguard(tag: u8) -> Vec<u8> {
    let mut packet = vec![4, 0, 0, 0];
    packet.extend_from_slice(&[tag; 28]);
    packet
}

impl World {
    /// Two nodes behind NATs that let nothing in, and a relay both may use.
    fn new() -> Self {
        let mut world = Self::without_relay();
        let server = world.relay.server();
        for node in &mut world.nodes {
            node.paths.set_relay_servers(vec![server]);
            node.dir.0.insert(server.node, world.relay.info());
        }
        world
    }

    fn without_relay() -> Self {
        let (mut a, mut b) = (side("192.0.2.10:1000"), side("203.0.113.20:2000"));
        let info = |s: &Side| PeerInfo {
            node_key: s.node,
            disco_key: s.disco,
            home_region: Some(REGION),
            endpoints: vec![s.addr].into(),
            relay_capable: true,
        };
        let (ia, ib) = (info(&a), info(&b));
        a.dir.0.insert(b.node, ib);
        b.dir.0.insert(a.node, ia);
        a.paths.set_endpoints(vec![a.addr]);
        b.paths.set_endpoints(vec![b.addr]);
        Self {
            nodes: [a, b],
            relay: Relay::new(),
            net: Net {
                direct: false,
                relay: true,
            },
            now: Instant::from_micros(1_000_000),
            wire: VecDeque::new(),
            to_relay: 0,
        }
    }

    fn peer(&self, i: usize) -> NodePublic {
        self.nodes[1 - i].node
    }

    /// Node `i` sends its peer a WireGuard datagram.
    fn send(&mut self, i: usize, tag: u8) {
        let (peer, now) = (self.peer(i), self.now);
        let node = &mut self.nodes[i];
        let out = node.paths.route(&peer, wireguard(tag), now, &node.dir);
        self.wire.extend(out.into_iter().map(|t| (i, t)));
    }

    /// A datagram for node `to`, from `src`.
    fn udp(&mut self, to: usize, src: SocketAddr, data: &[u8]) {
        let now = self.now;
        let node = &mut self.nodes[to];
        let out = if let Some((header, payload)) = geneve::unwrap(data) {
            match header.protocol {
                geneve::Protocol::Disco => node
                    .paths
                    .on_relayed_disco(payload, src, header, now, &node.dir),
                geneve::Protocol::WireGuard => {
                    node.got.push(("relay", payload.to_vec()));
                    Vec::new()
                }
            }
        } else if disco::looks_like_disco(data) {
            node.paths.on_disco(data, Via::Udp(src), now, &node.dir)
        } else {
            node.got.push(("direct", data.to_vec()));
            Vec::new()
        };
        self.wire.extend(out.into_iter().map(|t| (to, t)));
    }

    fn carry(&mut self, from: usize, t: Transmit) {
        let now = self.now;
        match t.via {
            Via::Derp { region, peer } => {
                assert_eq!(region, REGION);
                if peer == self.relay.node {
                    if let Some(answer) = self.relay.on_derp(&t.data) {
                        let via = Via::Derp {
                            region,
                            peer: self.relay.node,
                        };
                        let node = &mut self.nodes[from];
                        let out = node.paths.on_disco(&answer, via, now, &node.dir);
                        self.wire.extend(out.into_iter().map(|t| (from, t)));
                    }
                    return;
                }
                assert_eq!(peer, self.peer(from));
                let via = Via::Derp {
                    region,
                    peer: self.nodes[from].node,
                };
                let node = &mut self.nodes[1 - from];
                if disco::looks_like_disco(&t.data) {
                    let out = node.paths.on_disco(&t.data, via, now, &node.dir);
                    self.wire.extend(out.into_iter().map(|t| (1 - from, t)));
                } else {
                    node.got.push(("derp", t.data));
                }
            }
            Via::Udp(addr) if addr == self.relay.addr => {
                self.to_relay += 1;
                if !self.net.relay {
                    return;
                }
                let src = self.nodes[from].addr;
                if let Some((to, data)) = self.relay.on_udp(src, &t.data) {
                    // To where that client bound from: if it has moved
                    // since, nobody is there.
                    if let Some(to) = self.nodes.iter().position(|n| n.addr == to) {
                        self.udp(to, self.relay.addr, &data);
                    }
                }
            }
            Via::Udp(addr) => {
                if self.net.direct && addr == self.nodes[1 - from].addr {
                    self.udp(1 - from, self.nodes[from].addr, &t.data);
                }
            }
        }
    }

    fn settle(&mut self) {
        while let Some((from, t)) = self.wire.pop_front() {
            self.carry(from, t);
        }
    }

    /// `seconds` of both nodes talking to each other: a datagram each way
    /// and the timers, every 250 ms.
    fn talk(&mut self, seconds: u64) {
        for step in 0..seconds * 4 {
            self.now += Duration::from_millis(250);
            for i in 0..2 {
                self.send(i, step as u8);
                let now = self.now;
                let node = &mut self.nodes[i];
                let out = node.paths.tick(now, &node.dir);
                self.wire.extend(out.into_iter().map(|t| (i, t)));
            }
            self.settle();
        }
    }

    /// How node `i` reaches its peer right now.
    fn how(&self, i: usize) -> &'static str {
        let (paths, peer) = (&self.nodes[i].paths, self.peer(i));
        if paths.relayed(&peer, self.now).is_some() {
            "relay"
        } else if paths.direct(&peer, self.now).is_some() {
            "direct"
        } else {
            match paths.via(&peer, self.now) {
                Some(Via::Derp { .. }) => "derp",
                Some(Via::Udp(_)) => unreachable!("a UDP path that is neither"),
                None => "idle",
            }
        }
    }

    /// How the WireGuard datagrams node `i` got since the last call came.
    fn arrivals(&mut self, i: usize) -> Vec<&'static str> {
        let mut ways: Vec<&'static str> = self.nodes[i].got.drain(..).map(|(way, _)| way).collect();
        ways.dedup();
        ways
    }
}

/// No direct path, a relay both may use: within seconds both are on it, and
/// WireGuard goes through it, whole, instead of through DERP.
#[test]
fn without_a_direct_path_the_relay_carries_wireguard() {
    let mut world = World::new();
    world.now += Duration::from_millis(250);
    world.send(0, 1);
    world.send(1, 1);
    world.settle();
    assert_eq!(world.arrivals(0), ["derp"], "DERP until a path is proven");
    assert_eq!(world.arrivals(1), ["derp"]);
    world.talk(4);
    assert_eq!((world.how(0), world.how(1)), ("relay", "relay"));
    let relay = world.relay.addr;
    assert_eq!(
        world.nodes[0].paths.relayed(&world.peer(0), world.now),
        Some(relay)
    );
    assert_eq!(
        world.nodes[0].paths.via(&world.peer(0), world.now),
        Some(Via::Udp(relay))
    );
    assert_eq!(world.nodes[0].paths.direct(&world.peer(0), world.now), None);

    for node in &mut world.nodes {
        node.got.clear();
    }
    world.now += Duration::from_millis(250);
    world.send(0, 0xaa);
    world.send(1, 0xbb);
    world.settle();
    assert_eq!(world.nodes[1].got, [("relay", wireguard(0xaa))]);
    assert_eq!(world.nodes[0].got, [("relay", wireguard(0xbb))]);
    assert_eq!(world.relay.endpoints.len(), 1, "one endpoint for the pair");
}

/// The relay path is held: its heartbeats keep it trusted for as long as
/// the two talk, without a datagram going back to DERP.
#[test]
fn a_relay_path_holds_while_the_peers_talk() {
    let mut world = World::new();
    world.talk(5);
    world.arrivals(0);
    world.arrivals(1);
    for minute in 0..5 {
        world.talk(60);
        assert_eq!(
            (world.how(0), world.how(1)),
            ("relay", "relay"),
            "minute {minute}"
        );
        assert_eq!(world.arrivals(0), ["relay"], "minute {minute}");
        assert_eq!(world.arrivals(1), ["relay"], "minute {minute}");
    }
    // Asked again now and then (which keeps the peer told), never a second
    // endpoint for the same two.
    assert_eq!(world.relay.endpoints.len(), 1);
}

/// A direct path, once there is one, is taken over the relay whatever its
/// latency, and the relay is left alone.
#[test]
fn a_direct_path_replaces_the_relay() {
    let mut world = World::new();
    world.talk(5);
    assert_eq!((world.how(0), world.how(1)), ("relay", "relay"));
    world.net.direct = true;
    // Found by the full pings a peer without a direct path keeps sending.
    world.talk(70);
    assert_eq!((world.how(0), world.how(1)), ("direct", "direct"));
    world.arrivals(0);
    let (before, forwarded) = (world.to_relay, world.relay.forwarded);
    world.talk(120);
    assert_eq!(world.arrivals(0), ["direct"]);
    assert_eq!(world.to_relay, before, "nothing more to the relay");
    assert_eq!(world.relay.forwarded, forwarded);
}

/// The relay goes away: the path falls back to DERP within seconds, the
/// relay is asked again every 30 s, and taken again when it is back.
#[test]
fn a_relay_that_goes_away_is_fallen_back_from_and_found_again() {
    let mut world = World::new();
    world.talk(5);
    assert_eq!((world.how(0), world.how(1)), ("relay", "relay"));
    world.net.relay = false;
    world.talk(12);
    assert_eq!((world.how(0), world.how(1)), ("derp", "derp"));
    world.arrivals(0);
    world.talk(5);
    assert_eq!(world.arrivals(0), ["derp"], "DERP carries meanwhile");

    world.net.relay = true;
    world.talk(45);
    assert_eq!((world.how(0), world.how(1)), ("relay", "relay"));
    world.arrivals(0);
    world.talk(5);
    assert_eq!(world.arrivals(0), ["relay"]);
}

/// Without relay servers nothing of this happens: no request, no Geneve.
#[test]
fn without_relay_servers_nothing_is_asked() {
    let mut world = World::without_relay();
    world.talk(120);
    assert_eq!((world.how(0), world.how(1)), ("derp", "derp"));
    assert_eq!(world.to_relay, 0);
    assert!(world.relay.endpoints.is_empty());
}

/// A peer whose client is too old for relays is neither asked for nor
/// listened to about them.
#[test]
fn a_peer_that_does_not_speak_relay_is_left_on_derp() {
    let mut world = World::new();
    let peer = world.peer(0);
    world.nodes[0].dir.0.get_mut(&peer).unwrap().relay_capable = false;
    world.talk(60);
    // Node 1 allocates and tells node 0, which does not bind: no path.
    assert_eq!((world.how(0), world.how(1)), ("derp", "derp"));
    assert!(world
        .relay
        .endpoints
        .iter()
        .all(|e| e.bound[0].is_none() || e.bound[1].is_none()));
}

/// With direct paths off (DERP only) the relay, UDP too, is not used.
#[test]
fn derp_only_nodes_do_not_use_relays() {
    let mut world = World::new();
    for node in &mut world.nodes {
        node.paths.set_udp(false);
    }
    world.talk(60);
    assert_eq!((world.how(0), world.how(1)), ("derp", "derp"));
    assert_eq!(world.to_relay, 0);
}

/// The network changed: the relay path is forgotten with the direct ones,
/// and found again from the new address.
#[test]
fn a_rebind_drops_the_relay_path_and_finds_it_again() {
    let mut world = World::new();
    world.talk(5);
    assert_eq!(world.how(0), "relay");
    world.nodes[0].paths.reset_direct();
    world.nodes[0].addr = "192.0.2.10:1777".parse().unwrap();
    assert_eq!(world.how(0), "derp");
    world.talk(10);
    assert_eq!((world.how(0), world.how(1)), ("relay", "relay"));
    // The relay takes node 0 from its new address now.
    let endpoint = &world.relay.endpoints[0];
    assert!(endpoint.bound.contains(&Some(world.nodes[0].addr)));
}

/// What only a relay we are binding to, or a peer over DERP, may say is not
/// taken from anyone else.
#[test]
fn relay_messages_from_the_wrong_place_are_ignored() {
    let mut world = World::new();
    let (peer, now) = (world.peer(0), world.now);
    let stranger = PrivateKey::generate();
    let me = world.nodes[0].disco;
    let endpoint = RelayEndpoint {
        server: DiscoPublic(stranger.public()),
        clients: [me, world.nodes[1].disco],
        lamport_id: 1,
        vni: 77,
        bind_lifetime: Duration::from_secs(30),
        steady_state_lifetime: Duration::from_secs(300),
        addrs: vec!["198.51.100.66:6".parse().unwrap()],
    };
    let node = &mut world.nodes[0];
    let derp_from = |peer| Via::Derp {
        region: REGION,
        peer,
    };

    // A call-me-maybe-via must come over DERP, from the node its key is of.
    let stranger_via = disco::seal(&stranger, &me, &Message::CallMeMaybeVia(endpoint.clone()));
    assert!(node
        .paths
        .on_disco(&stranger_via, derp_from(peer), now, &node.dir)
        .is_empty());

    // An allocation nobody asked for, and a challenge with no handshake.
    let unasked = disco::seal(
        &world.relay.node_disco,
        &me,
        &Message::RelayAllocated {
            generation: 1,
            endpoint: endpoint.clone(),
        },
    );
    assert!(node
        .paths
        .on_disco(&unasked, derp_from(world.relay.node), now, &node.dir)
        .is_empty());
    let challenge = Message::RelayChallenge(RelayBind {
        vni: 77,
        generation: 1,
        remote: world.nodes[1].disco,
        challenge: [1; 32],
    });
    let control = geneve::Header {
        protocol: geneve::Protocol::Disco,
        vni: 77,
        control: true,
    };
    let sealed = disco::seal(&stranger, &me, &challenge);
    let src = "198.51.100.66:6".parse().unwrap();
    let node = &mut world.nodes[0];
    assert!(node
        .paths
        .on_relayed_disco(&sealed, src, control, now, &node.dir)
        .is_empty());

    // The peer's own call-me-maybe-via, but not over DERP.
    world.talk(5);
    assert_eq!(world.how(0), "relay");
    let real = &world.relay.endpoints[0];
    let description = RelayEndpoint {
        server: DiscoPublic(world.relay.bind_disco.public()),
        clients: real.clients,
        lamport_id: real.lamport_id + 9,
        vni: real.vni,
        ..endpoint
    };
    let before = world.to_relay;
    let (now, src) = (world.now, world.nodes[1].addr);
    // (Sealed by node 1 itself would need its key; a stranger's box is not
    // opened, and an unsealed path is refused before that.)
    let forged = disco::seal(&stranger, &me, &Message::CallMeMaybeVia(description));
    let node = &mut world.nodes[0];
    assert!(node
        .paths
        .on_disco(&forged, Via::Udp(src), now, &node.dir)
        .is_empty());
    assert_eq!(world.to_relay, before);
}
