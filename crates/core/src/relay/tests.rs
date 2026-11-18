//! The relay client against a relay server as tailscale's `net/udprelay`
//! behaves, both in memory: two clients, the messages between them carried
//! by hand so that any of them can be lost, doubled or late.

// The two clients are told apart by index throughout.
#![allow(clippy::needless_range_loop)]

use super::*;
use crate::keys::{PrivateKey, PublicKey};
use alloc::collections::VecDeque;

fn disco(fill: u8) -> DiscoPublic {
    DiscoPublic(PublicKey([fill; 32]))
}

fn node(fill: u8) -> NodePublic {
    NodePublic(PublicKey([fill; 32]))
}

fn at(millis: u64) -> Instant {
    Instant::from_micros(millis * 1000)
}

const SERVER_ADDR: &str = "198.51.100.1:40000";
const REGION: i32 = 7;

/// One endpoint of the simulated server.
struct Endpoint {
    vni: u32,
    clients: [DiscoPublic; 2],
    lamport_id: u64,
    /// Where each client bound from.
    bound: [Option<SocketAddr>; 2],
}

/// A relay server: allocations over DERP, the bind handshake, and
/// forwarding between two bound clients.
struct Server {
    me: super::Server,
    /// Its key for the bind handshake.
    disco: DiscoPublic,
    addr: SocketAddr,
    endpoints: Vec<Endpoint>,
    lamport: u64,
}

impl Server {
    fn new() -> Self {
        Self {
            me: super::Server {
                node: node(0xee),
                disco: disco(0xed),
                home_region: Some(REGION),
            },
            disco: disco(0xec),
            addr: SERVER_ADDR.parse().unwrap(),
            endpoints: Vec::new(),
            lamport: 0,
        }
    }

    /// The challenge for a bind from `src`: the server keeps none, it
    /// recomputes it (a MAC over the address, upstream).
    fn challenge(src: SocketAddr) -> [u8; 32] {
        let mut out = [0x5a; 32];
        out[..2].copy_from_slice(&src.port().to_be_bytes());
        out
    }

    /// An endpoint for the pair: the one it has, or a new one.
    fn allocate(&mut self, clients: [DiscoPublic; 2]) -> RelayEndpoint {
        let at = match self.endpoints.iter().position(|e| e.clients == clients) {
            Some(at) => at,
            None => {
                self.lamport += 1;
                self.endpoints.push(Endpoint {
                    vni: 100 + self.lamport as u32,
                    clients,
                    lamport_id: self.lamport,
                    bound: [None, None],
                });
                self.endpoints.len() - 1
            }
        };
        self.describe(at)
    }

    fn describe(&self, at: usize) -> RelayEndpoint {
        let e = &self.endpoints[at];
        RelayEndpoint {
            server: self.disco,
            clients: e.clients,
            lamport_id: e.lamport_id,
            vni: e.vni,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            addrs: vec![self.addr],
        }
    }

    /// A datagram under `vni` from `sender` at `src`. Returns what the
    /// server sends: an answer to `src`, or the message forwarded.
    fn datagram(
        &mut self,
        sender: DiscoPublic,
        src: SocketAddr,
        vni: u32,
        control: bool,
        msg: &Message,
    ) -> Option<(SocketAddr, Message)> {
        let e = self.endpoints.iter_mut().find(|e| e.vni == vni)?;
        if !control {
            // Forwarded by where it comes from, to where the other bound.
            let from = e.bound.iter().position(|b| *b == Some(src))?;
            return Some((e.bound[1 - from]?, msg.clone()));
        }
        let index = e.clients.iter().position(|c| *c == sender)?;
        let other = e.clients[1 - index];
        match msg {
            Message::RelayBind(bind)
                if bind.vni == vni && bind.remote == other && bind.generation != 0 =>
            {
                Some((
                    src,
                    Message::RelayChallenge(RelayBind {
                        vni,
                        generation: bind.generation,
                        remote: other,
                        challenge: Self::challenge(src),
                    }),
                ))
            }
            Message::RelayAnswer(answer)
                if answer.vni == vni
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

struct Client {
    relay: RelayClient,
    me: Remote,
    addr: SocketAddr,
    ready: Option<Ready>,
}

/// What a message in flight is.
#[derive(Debug, Clone)]
enum Packet {
    /// From client `from` (an index), as it asked.
    Sent { from: usize, send: Send },
    /// From the server to client `to`: over DERP, or from its address.
    Derp { to: usize, msg: Message },
    Relayed {
        to: usize,
        /// Whose box it is in: the server's (control) or the other client's.
        sender: DiscoPublic,
        vni: u32,
        control: bool,
        msg: Message,
    },
}

/// What happens to a packet on the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    Deliver,
    Drop,
    Twice,
}

struct World {
    clients: [Client; 2],
    server: Server,
    now: Instant,
    wire: VecDeque<Packet>,
    /// Every message the clients sent, for the tests to look at.
    sent: Vec<(usize, Send)>,
}

impl World {
    fn new() -> Self {
        let client = |fill: u8, addr: &str| {
            let me = Remote {
                node: node(fill),
                disco: disco(fill + 1),
                home_region: Some(REGION),
            };
            Client {
                relay: RelayClient::new(me.disco, me.node),
                me,
                addr: addr.parse().unwrap(),
                ready: None,
            }
        };
        let mut world = Self {
            clients: [
                client(0x10, "192.0.2.10:1000"),
                client(0x20, "203.0.113.20:2000"),
            ],
            server: Server::new(),
            now: at(0),
            wire: VecDeque::new(),
            sent: Vec::new(),
        };
        for c in &mut world.clients {
            c.relay.set_servers(vec![world.server.me]);
        }
        world
    }

    fn other(&self, i: usize) -> Remote {
        self.clients[1 - i].me
    }

    fn queue(&mut self, from: usize, out: Vec<Send>) {
        for send in out {
            self.sent.push((from, send.clone()));
            self.wire.push_back(Packet::Sent { from, send });
        }
    }

    fn discover(&mut self, i: usize) {
        let (remote, mut out) = (self.other(i), Vec::new());
        self.clients[i].relay.discover(&remote, self.now, &mut out);
        self.queue(i, out);
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        for i in 0..2 {
            let mut out = Vec::new();
            self.clients[i].relay.tick(self.now, &mut out);
            self.queue(i, out);
        }
    }

    /// Carry one packet.
    fn carry(&mut self, packet: Packet) {
        match packet {
            Packet::Sent {
                from,
                send: Send::Derp {
                    node, disco, msg, ..
                },
            } => {
                if node == self.server.me.node {
                    assert_eq!(disco, self.server.me.disco, "sealed to the server's node");
                    if let Message::AllocateRelay {
                        clients,
                        generation,
                    } = msg
                    {
                        let endpoint = self.server.allocate(clients);
                        self.wire.push_back(Packet::Derp {
                            to: from,
                            msg: Message::RelayAllocated {
                                generation,
                                endpoint,
                            },
                        });
                    }
                } else {
                    assert_eq!(node, self.other(from).node);
                    assert_eq!(disco, self.other(from).disco);
                    self.wire.push_back(Packet::Derp { to: 1 - from, msg });
                }
            }
            Packet::Sent {
                from,
                send:
                    Send::Relay {
                        addr,
                        vni,
                        control,
                        disco,
                        msg,
                    },
            } => {
                assert_eq!(addr, self.server.addr);
                let expected = if control {
                    self.server.disco
                } else {
                    self.other(from).disco
                };
                assert_eq!(disco, expected, "sealed to whom it is for");
                let (sender, src) = (self.clients[from].me.disco, self.clients[from].addr);
                if let Some((to, msg)) = self.server.datagram(sender, src, vni, control, &msg) {
                    let (to, sender) = if to == src {
                        (from, self.server.disco)
                    } else {
                        (1 - from, sender)
                    };
                    self.wire.push_back(Packet::Relayed {
                        to,
                        sender,
                        vni,
                        control: sender == self.server.disco,
                        msg,
                    });
                }
            }
            Packet::Derp { to, msg } => {
                let (remote, now, mut out) = (self.other(to), self.now, Vec::new());
                match msg {
                    Message::RelayAllocated {
                        generation,
                        endpoint,
                    } => {
                        let from = self.server.me.node;
                        let relay = &mut self.clients[to].relay;
                        relay.on_allocated(&from, generation, endpoint, |_| None, now, &mut out);
                    }
                    Message::CallMeMaybeVia(endpoint) => {
                        let relay = &mut self.clients[to].relay;
                        relay.on_call_me_maybe_via(&remote, endpoint, None, now, &mut out);
                    }
                    other => panic!("unexpected over DERP: {other:?}"),
                }
                self.queue(to, out);
            }
            Packet::Relayed {
                to,
                sender,
                vni,
                control,
                msg,
            } => {
                let (src, now, mut out) = (self.server.addr, self.now, Vec::new());
                let client = &mut self.clients[to];
                match msg {
                    Message::RelayChallenge(challenge) => {
                        assert!(control);
                        if client.relay.expects(&sender) {
                            client
                                .relay
                                .on_challenge(&sender, src, vni, &challenge, now, &mut out);
                        }
                    }
                    Message::Ping { tx, .. } => {
                        // The caller's part: always a pong, the way it came.
                        out.push(Send::Relay {
                            addr: src,
                            vni,
                            control: false,
                            disco: sender,
                            msg: Message::Pong { tx, src },
                        });
                        client.relay.on_ping(&sender, src, vni, now, &mut out);
                    }
                    Message::Pong { tx, .. } => {
                        if let Some(ready) = client.relay.on_pong(&sender, src, vni, &tx, now) {
                            client.ready = Some(ready);
                        }
                    }
                    other => panic!("unexpected through the relay: {other:?}"),
                }
                self.queue(to, out);
            }
        }
    }

    /// Carry everything in flight, and what that brings, in order.
    fn settle(&mut self) {
        while let Some(packet) = self.wire.pop_front() {
            self.carry(packet);
        }
    }

    fn asked(&self, from: usize, what: impl Fn(&Send) -> bool) -> usize {
        self.sent
            .iter()
            .filter(|(i, send)| *i == from && what(send))
            .count()
    }
}

fn is_allocate(send: &Send) -> bool {
    matches!(
        send,
        Send::Derp {
            msg: Message::AllocateRelay { .. },
            ..
        }
    )
}

fn is_via(send: &Send) -> bool {
    matches!(
        send,
        Send::Derp {
            msg: Message::CallMeMaybeVia(_),
            ..
        }
    )
}

fn is_bind(send: &Send) -> bool {
    matches!(
        send,
        Send::Relay {
            msg: Message::RelayBind(_),
            control: true,
            ..
        }
    )
}

fn is_ping(send: &Send) -> bool {
    matches!(
        send,
        Send::Relay {
            msg: Message::Ping { .. },
            control: false,
            ..
        }
    )
}

/// One side asks, both end up on the relay: allocated, the peer told, both
/// bound, a pong each way.
#[test]
fn one_side_allocates_and_both_bind() {
    let mut world = World::new();
    world.discover(0);
    world.settle();
    for (i, client) in world.clients.iter().enumerate() {
        let ready = client
            .ready
            .unwrap_or_else(|| panic!("client {i} has no relay path"));
        assert_eq!(ready.peer, world.clients[1 - i].me.node);
        assert_eq!(ready.addr, world.server.addr);
        assert_eq!(ready.server, world.server.disco);
        assert_eq!(ready.vni, world.server.endpoints[0].vni);
        assert_eq!(client.relay.work(), 0, "nothing left under way");
    }
    assert_eq!(world.asked(0, is_allocate), 1);
    assert_eq!(
        world.asked(0, is_via),
        1,
        "the peer is told of our endpoint"
    );
    assert_eq!(world.asked(1, is_allocate), 0, "the peer only answers");
    assert_eq!(world.asked(1, is_via), 0);
    // The server took each client's own address.
    assert_eq!(
        world.server.endpoints[0].bound,
        [Some(world.clients[0].addr), Some(world.clients[1].addr)]
    );
}

/// Both ask at once: the server hands both the same endpoint, and the
/// duplicate descriptions (one's own, the peer's) start one handshake each.
#[test]
fn both_sides_asking_share_one_endpoint() {
    let mut world = World::new();
    world.discover(0);
    world.discover(1);
    world.settle();
    assert_eq!(world.server.endpoints.len(), 1);
    for i in 0..2 {
        assert!(world.clients[i].ready.is_some(), "client {i}");
        assert_eq!(world.asked(i, is_bind), 1, "client {i} bound once");
        assert_eq!(world.clients[i].relay.work(), 0);
    }
}

/// An allocation request DERP lost is sent once more after 3 s, and given
/// up after 10: then a later discovery asks anew.
#[test]
fn an_unanswered_allocation_is_asked_again_then_dropped() {
    let mut world = World::new();
    world.discover(0);
    world.wire.clear(); // lost
    assert_eq!(world.clients[0].relay.next_deadline(), Some(at(3000)));
    world.advance(Duration::from_millis(2999));
    assert_eq!(world.asked(0, is_allocate), 1);
    world.advance(Duration::from_millis(1));
    assert_eq!(world.asked(0, is_allocate), 2, "asked again at 3 s");
    world.wire.clear(); // lost again
    world.advance(Duration::from_secs(5));
    assert_eq!(world.asked(0, is_allocate), 2, "only once more");
    assert!(world.clients[0].relay.busy_with(&world.other(0).node));
    world.discover(0);
    assert_eq!(world.asked(0, is_allocate), 2, "not while one is under way");
    world.advance(Duration::from_secs(2));
    assert!(!world.clients[0].relay.busy_with(&world.other(0).node));
    assert_eq!(world.clients[0].relay.next_deadline(), None);

    world.discover(0);
    world.settle();
    assert!(world.clients[0].ready.is_some() && world.clients[1].ready.is_some());
}

/// The second request is the one answered: it carries the same generation.
#[test]
fn the_retried_request_is_answered_like_the_first() {
    let mut world = World::new();
    world.discover(0);
    world.wire.clear();
    world.advance(ALLOCATE_RETRY);
    world.settle();
    assert!(world.clients[0].ready.is_some() && world.clients[1].ready.is_some());
}

/// An answer is taken only from the server asked, for the request made and
/// the two of us.
#[test]
fn allocation_answers_must_match_the_request() {
    let mut world = World::new();
    world.discover(0);
    world.wire.clear();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (server, now) = (world.server.me.node, world.now);
    let mut out = Vec::new();
    let relay = &mut world.clients[0].relay;

    // Someone else answering.
    relay.on_allocated(&node(0x99), 1, endpoint.clone(), |_| None, now, &mut out);
    // Another request's number.
    relay.on_allocated(&server, 2, endpoint.clone(), |_| None, now, &mut out);
    // An endpoint for another pair.
    let mut other = endpoint.clone();
    other.clients = pair(world.clients[0].me.disco, disco(0x77));
    relay.on_allocated(&server, 1, other, |_| None, now, &mut out);
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(relay.work(), 1, "still waiting");

    relay.on_allocated(&server, 1, endpoint.clone(), |_| None, now, &mut out);
    assert!(out.iter().any(is_bind) && out.iter().any(is_via));
    // And only once: a doubled answer finds no request.
    let before = out.len();
    relay.on_allocated(&server, 1, endpoint, |_| None, now, &mut out);
    assert_eq!(out.len(), before);
}

/// A call-me-maybe-via for an endpoint that is not ours, has no VNI or
/// nowhere to send to starts nothing.
#[test]
fn endpoints_that_cannot_be_ours_are_refused() {
    let mut world = World::new();
    let good = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (remote, now) = (world.other(0), world.now);
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();

    let mut for_others = good.clone();
    for_others.clients = [disco(0x71), disco(0x72)];
    let mut not_us = good.clone();
    not_us.clients = pair(remote.disco, disco(0x73));
    let mut no_vni = good.clone();
    no_vni.vni = 0;
    let mut wide_vni = good.clone();
    wide_vni.vni = VNI_MAX + 1;
    let mut nowhere = good.clone();
    nowhere.addrs = vec![
        "0.0.0.0:40000".parse().unwrap(),
        "198.51.100.1:0".parse().unwrap(),
    ];
    for bad in [for_others, not_us, no_vni, wide_vni, nowhere] {
        relay.on_call_me_maybe_via(&remote, bad.clone(), None, now, &mut out);
        assert!(out.is_empty(), "{bad:?}");
        assert_eq!(relay.work(), 0);
    }
    relay.on_call_me_maybe_via(&remote, good, None, now, &mut out);
    assert_eq!(out.len(), 1);
    assert!(is_bind(&out[0]));
}

/// A bind goes to every address of the server that can be sent to; the
/// first challenge is the one answered, from where it came.
#[test]
fn binds_go_to_every_address_and_one_challenge_is_answered() {
    let mut world = World::new();
    let mut endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let second: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
    endpoint.addrs = vec![world.server.addr, "0.0.0.0:1".parse().unwrap(), second];
    let (remote, now, server) = (world.other(0), world.now, world.server.disco);
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, endpoint.clone(), None, now, &mut out);
    let binds: Vec<SocketAddr> = out
        .iter()
        .filter_map(|s| match s {
            Send::Relay {
                addr,
                msg: Message::RelayBind(_),
                ..
            } => Some(*addr),
            _ => None,
        })
        .collect();
    assert_eq!(binds, [world.server.addr, second]);
    let Send::Relay {
        msg: Message::RelayBind(bind),
        ..
    } = out[0].clone()
    else {
        panic!()
    };
    assert_ne!(bind.generation, 0, "the server drops generation 0");
    assert_eq!((bind.vni, bind.remote), (endpoint.vni, remote.disco));

    let challenge = |fill: u8| RelayBind {
        vni: endpoint.vni,
        generation: bind.generation,
        remote: remote.disco,
        challenge: [fill; 32],
    };
    out.clear();
    relay.on_challenge(&server, second, endpoint.vni, &challenge(1), now, &mut out);
    // The answer echoes the challenge to where it came from, a ping behind it.
    assert_eq!(out.len(), 2);
    assert!(
        matches!(&out[0], Send::Relay { addr, control: true, disco, msg: Message::RelayAnswer(a), .. }
        if *addr == second && *disco == server && a.challenge == [1; 32])
    );
    assert!(
        matches!(&out[1], Send::Relay { addr, control: false, disco, msg: Message::Ping { node_key: Some(_), .. }, .. }
        if *addr == second && *disco == remote.disco)
    );
    // The other address's challenge comes too late.
    out.clear();
    relay.on_challenge(
        &server,
        world.server.addr,
        endpoint.vni,
        &challenge(2),
        now,
        &mut out,
    );
    assert!(out.is_empty(), "{out:?}");
}

/// A challenge is answered only if it is this handshake's: the server's key,
/// the header's VNI sealed inside, our peer, our generation.
#[test]
fn challenges_that_are_not_ours_are_ignored() {
    let mut world = World::new();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (remote, now, server, src) = (
        world.other(0),
        world.now,
        world.server.disco,
        world.server.addr,
    );
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, endpoint.clone(), None, now, &mut out);
    let Send::Relay {
        msg: Message::RelayBind(bind),
        ..
    } = out[0].clone()
    else {
        panic!()
    };
    out.clear();
    let good = RelayBind {
        challenge: [3; 32],
        ..bind
    };

    assert!(!relay.expects(&disco(0x55)));
    relay.on_challenge(&disco(0x55), src, endpoint.vni, &good, now, &mut out);
    // The header's VNI changed on the way (the sealed one says otherwise).
    relay.on_challenge(&server, src, endpoint.vni + 1, &good, now, &mut out);
    relay.on_challenge(
        &server,
        src,
        endpoint.vni,
        &RelayBind {
            vni: endpoint.vni + 1,
            ..good.clone()
        },
        now,
        &mut out,
    );
    relay.on_challenge(
        &server,
        src,
        endpoint.vni,
        &RelayBind {
            remote: disco(0x56),
            ..good.clone()
        },
        now,
        &mut out,
    );
    relay.on_challenge(
        &server,
        src,
        endpoint.vni,
        &RelayBind {
            generation: good.generation + 1,
            ..good.clone()
        },
        now,
        &mut out,
    );
    assert!(out.is_empty(), "{out:?}");

    assert!(relay.expects(&server));
    relay.on_challenge(&server, src, endpoint.vni, &good, now, &mut out);
    assert_eq!(out.len(), 2);
}

/// Our first ping is dropped while the peer has not bound. Its ping, once
/// it has, is answered with another of ours, and that one's pong counts.
#[test]
fn a_ping_from_the_peer_triggers_another_of_ours() {
    let mut world = World::new();
    world.discover(0);
    // Client 0 through to its answer and first ping, client 1 not yet told.
    let mut held = Vec::new();
    while let Some(packet) = world.wire.pop_front() {
        match packet {
            Packet::Derp { to: 1, .. } => held.push(packet),
            packet => world.carry(packet),
        }
    }
    assert_eq!(world.asked(0, is_ping), 1);
    assert!(world.clients[0].ready.is_none(), "its ping went nowhere");
    assert_eq!(world.server.endpoints[0].bound[1], None);

    world.wire.extend(held);
    world.settle();
    assert_eq!(world.asked(0, is_ping), 2, "one more, for the peer's ping");
    assert!(world.clients[0].ready.is_some() && world.clients[1].ready.is_some());
}

/// A peer cannot have us ping without end.
#[test]
fn pings_per_handshake_are_bounded() {
    let mut world = World::new();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (remote, now, server, src) = (
        world.other(0),
        world.now,
        world.server.disco,
        world.server.addr,
    );
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, endpoint.clone(), None, now, &mut out);
    let Send::Relay {
        msg: Message::RelayBind(bind),
        ..
    } = out[0].clone()
    else {
        panic!()
    };
    // Before the answer, a relayed ping is not ours to follow.
    out.clear();
    relay.on_ping(&remote.disco, src, endpoint.vni, now, &mut out);
    assert!(out.is_empty());
    relay.on_challenge(&server, src, endpoint.vni, &bind, now, &mut out);
    for _ in 0..50 {
        relay.on_ping(&remote.disco, src, endpoint.vni, now, &mut out);
    }
    assert_eq!(out.iter().filter(|s| is_ping(s)).count(), MAX_PINGS);
    // Someone else's ping, or one under another VNI, is not this handshake's.
    out.clear();
    relay.on_ping(&disco(0x44), src, endpoint.vni, now, &mut out);
    relay.on_ping(&remote.disco, src, endpoint.vni + 1, now, &mut out);
    assert!(out.is_empty());
}

/// Only the pong of a ping this handshake sent, from where it bound, makes
/// the path ready; its latency is that ping's.
#[test]
fn only_our_own_ping_s_pong_makes_the_path_ready() {
    let mut world = World::new();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (remote, server, src) = (world.other(0), world.server.disco, world.server.addr);
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, endpoint.clone(), None, at(0), &mut out);
    let Send::Relay {
        msg: Message::RelayBind(bind),
        ..
    } = out[0].clone()
    else {
        panic!()
    };
    out.clear();
    relay.on_challenge(&server, src, endpoint.vni, &bind, at(100), &mut out);
    let Send::Relay {
        msg: Message::Ping { tx, .. },
        ..
    } = out[1].clone()
    else {
        panic!()
    };
    let elsewhere: SocketAddr = "198.51.100.9:9".parse().unwrap();
    assert_eq!(
        relay.on_pong(&remote.disco, src, endpoint.vni, &[0; 12], at(140)),
        None
    );
    assert_eq!(
        relay.on_pong(&disco(0x44), src, endpoint.vni, &tx, at(140)),
        None
    );
    assert_eq!(
        relay.on_pong(&remote.disco, elsewhere, endpoint.vni, &tx, at(140)),
        None
    );
    assert_eq!(
        relay.on_pong(&remote.disco, src, endpoint.vni + 1, &tx, at(140)),
        None
    );
    assert_eq!(relay.work(), 1);
    let ready = relay
        .on_pong(&remote.disco, src, endpoint.vni, &tx, at(140))
        .unwrap();
    assert_eq!(ready.latency, Duration::from_millis(40));
    assert_eq!(
        (ready.addr, ready.vni, ready.server),
        (src, endpoint.vni, server)
    );
    assert_eq!(relay.work(), 0);
    // The handshake is over: the same pong again is nobody's.
    assert_eq!(
        relay.on_pong(&remote.disco, src, endpoint.vni, &tx, at(141)),
        None
    );
}

/// A handshake nobody answers ends at the endpoint's bind lifetime, 30 s at
/// most whatever the server says.
#[test]
fn handshakes_end_at_the_bind_lifetime_or_thirty_seconds() {
    for (lifetime, ends) in [(5, 5), (30, 30), (3600, 30)] {
        let mut world = World::new();
        let mut endpoint = world
            .server
            .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
        endpoint.bind_lifetime = Duration::from_secs(lifetime);
        let remote = world.other(0);
        let relay = &mut world.clients[0].relay;
        let mut out = Vec::new();
        relay.on_call_me_maybe_via(&remote, endpoint, None, at(0), &mut out);
        // The bind goes again every 2 s, three times, and then it waits.
        out.clear();
        let mut now = at(0);
        while let Some(due) = relay.next_deadline() {
            assert!(due > now, "a deadline that does not pass");
            now = due;
            if now >= at(ends * 1000) {
                break;
            }
            assert_eq!(relay.work(), 1, "still trying at {now:?}");
            relay.tick(now, &mut out);
        }
        // As many as fit before the end: two in 5 s.
        let fit = ((ends * 1000 - 1) / 2000).min(BIND_RETRIES as u64) as usize;
        assert_eq!(out.iter().filter(|s| is_bind(s)).count(), fit);
        assert_eq!(now, at(ends * 1000), "lifetime {lifetime} s");
        relay.tick(now, &mut out);
        assert_eq!(relay.work(), 0);
        assert_eq!(relay.next_deadline(), None);
    }
}

/// Of two descriptions of a server's endpoint the later (by Lamport id)
/// wins: an older or equal one changes nothing, a newer one starts over.
#[test]
fn the_later_description_of_an_endpoint_wins() {
    let mut world = World::new();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let remote = world.other(0);
    let relay = &mut world.clients[0].relay;
    let with = |lamport_id: u64, vni: u32| RelayEndpoint {
        lamport_id,
        vni,
        ..endpoint.clone()
    };
    let generation = |out: &[Send]| match &out[0] {
        Send::Relay {
            msg: Message::RelayBind(bind),
            ..
        } => bind.generation,
        other => panic!("{other:?}"),
    };
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, with(5, 200), None, at(0), &mut out);
    let first = generation(&out);

    for stale in [with(5, 200), with(4, 200), with(4, 201)] {
        out.clear();
        relay.on_call_me_maybe_via(&remote, stale, None, at(1), &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(relay.work(), 1);
    }
    // The server allocated anew for the two of us (another VNI, a later id):
    // the old handshake is dropped for it.
    out.clear();
    relay.on_call_me_maybe_via(&remote, with(6, 201), None, at(2), &mut out);
    assert_eq!(relay.work(), 1);
    assert_ne!(generation(&out), first, "a new handshake, a new generation");
    let Send::Relay { vni, .. } = out[0] else {
        panic!()
    };
    assert_eq!(vni, 201);
}

/// On the endpoint already, and it answers: no new handshake (the relay
/// takes one source address per peer), but the peer is still told of an
/// endpoint we allocated.
#[test]
fn a_trusted_path_on_the_endpoint_is_left_alone() {
    let mut world = World::new();
    world.discover(0);
    world.wire.clear();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (server, now, peer) = (world.server.me.node, world.now, world.other(0).node);
    let on_it = |trusted: bool| {
        let (server, vni) = (endpoint.server, endpoint.vni);
        move |node: &NodePublic| {
            assert_eq!(*node, peer);
            Some(Current {
                server,
                vni,
                trusted,
            })
        }
    };
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_allocated(&server, 1, endpoint.clone(), on_it(true), now, &mut out);
    assert_eq!(out.len(), 1);
    assert!(is_via(&out[0]), "{out:?}");
    assert_eq!(relay.work(), 0);

    // Not trusted any more: bind again.
    let mut out = Vec::new();
    let remote = world.other(0);
    let relay = &mut world.clients[0].relay;
    relay.discover(&remote, now, &mut out);
    out.clear();
    relay.on_allocated(&server, 2, endpoint.clone(), on_it(false), now, &mut out);
    assert!(out.iter().any(is_bind));
}

/// A peer is not reached through itself, a server without a DERP home
/// cannot be asked, and work is bounded whatever the number of servers.
#[test]
fn discovery_asks_the_servers_that_can_help() {
    let mut world = World::new();
    let remote = world.other(0);
    let server = |fill: u8, home_region| super::Server {
        node: node(fill),
        disco: disco(fill),
        home_region,
    };
    let me = world.clients[0].me.disco;
    let relay = &mut world.clients[0].relay;
    relay.set_servers(vec![
        super::Server {
            node: remote.node,
            disco: remote.disco,
            home_region: Some(REGION),
        },
        server(0xa1, None),
        server(0xa2, Some(3)),
        server(0xa3, Some(4)),
    ]);
    let mut out = Vec::new();
    relay.discover(&remote, at(0), &mut out);
    let asked: Vec<(i32, NodePublic)> = out
        .iter()
        .map(|s| match s {
            Send::Derp {
                region,
                node,
                msg: Message::AllocateRelay { clients, .. },
                ..
            } => {
                assert_eq!(*clients, pair(me, remote.disco));
                (*region, *node)
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(asked, [(3, node(0xa2)), (4, node(0xa3))]);

    // A server that left takes its request with it.
    relay.set_servers(vec![server(0xa3, Some(4))]);
    assert_eq!(relay.work(), 1);
    relay.forget(&remote.node);
    assert_eq!(relay.work(), 0);

    // Many servers, many peers: never more than MAX_WORK under way.
    relay.set_servers((0..100u8).map(|i| server(i, Some(1))).collect());
    out.clear();
    for peer in 0..10u8 {
        let remote = Remote {
            node: node(200 + peer),
            disco: disco(200 + peer),
            home_region: Some(1),
        };
        relay.discover(&remote, at(0), &mut out);
    }
    assert_eq!(relay.work(), MAX_WORK);
    assert_eq!(out.len(), MAX_WORK);
    relay.reset();
    assert_eq!(relay.work(), 0);
}

/// A lost answer leaves the relay not knowing us, and our ping dropped
/// behind it: both go again every 2 s while the handshake has pings left.
#[test]
fn an_answer_is_repeated_with_its_ping() {
    let mut world = World::new();
    let endpoint = world
        .server
        .allocate(pair(world.clients[0].me.disco, world.clients[1].me.disco));
    let (remote, server, src) = (world.other(0), world.server.disco, world.server.addr);
    let relay = &mut world.clients[0].relay;
    let mut out = Vec::new();
    relay.on_call_me_maybe_via(&remote, endpoint.clone(), None, at(0), &mut out);
    let Send::Relay {
        msg: Message::RelayBind(bind),
        ..
    } = out[0].clone()
    else {
        panic!()
    };
    let challenge = RelayBind {
        challenge: [8; 32],
        ..bind
    };
    out.clear();
    relay.on_challenge(&server, src, endpoint.vni, &challenge, at(500), &mut out);
    assert_eq!(relay.next_deadline(), Some(at(2500)));
    out.clear();
    relay.tick(at(2499), &mut out);
    assert!(out.is_empty());
    relay.tick(at(2500), &mut out);
    assert!(
        matches!(&out[..], [
        Send::Relay { control: true, msg: Message::RelayAnswer(a), .. },
        Send::Relay { control: false, msg: Message::Ping { .. }, .. },
    ] if a.challenge == [8; 32]),
        "{out:?}"
    );
    // Until the pings are spent; no bind again once answered.
    out.clear();
    for second in 1..40 {
        relay.tick(at(2500 + second * 2000), &mut out);
    }
    assert_eq!(out.iter().filter(|s| is_ping(s)).count(), MAX_PINGS - 2);
    assert!(!out.iter().any(is_bind));
}

/// A small deterministic generator, so that a failing run can be repeated.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The network at its worst: a third of all messages lost, some doubled,
/// all of them out of order, with the clients asking again every 30 s as
/// path selection does. Whatever arrives in whatever order, nothing panics,
/// the work stays bounded, and a path through the relay comes up for both.
#[test]
fn a_lossy_reordering_network_still_gets_both_on_the_relay() {
    for seed in 1..=300u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut world = World::new();
        let mut asked_at = [None::<Instant>; 2];
        let mut done_at = None;
        for step in 0..2400u64 {
            // 250 ms a step: ten minutes at most.
            for i in 0..2 {
                let due = asked_at[i].is_none_or(|t| {
                    world.now.saturating_duration_since(t) >= Duration::from_secs(30)
                });
                if world.clients[i].ready.is_none() && due && rng.below(2) == 0 {
                    asked_at[i] = Some(world.now);
                    world.discover(i);
                }
            }
            // A client on the relay keeps its path up, as path selection
            // does: a ping through it every 3 s.
            if step % 12 == 0 {
                for i in 0..2 {
                    if let Some(ready) = world.clients[i].ready {
                        let ping = Send::Relay {
                            addr: ready.addr,
                            vni: ready.vni,
                            control: false,
                            disco: world.other(i).disco,
                            msg: Message::Ping {
                                tx: [step as u8; 12],
                                node_key: None,
                            },
                        };
                        world.queue(i, vec![ping]);
                    }
                }
            }
            // Some of what is in flight arrives, in any order.
            for _ in 0..rng.below(8) {
                if world.wire.is_empty() {
                    break;
                }
                let at = rng.below(world.wire.len() as u64) as usize;
                let packet = world.wire.remove(at).unwrap();
                let fate = match rng.below(100) {
                    0..=32 => Fate::Drop,
                    33..=42 => Fate::Twice,
                    _ => Fate::Deliver,
                };
                if fate == Fate::Twice {
                    world.carry(packet.clone());
                }
                if fate != Fate::Drop {
                    world.carry(packet);
                }
            }
            for client in &world.clients {
                assert!(client.relay.work() <= MAX_WORK, "seed {seed}");
            }
            if world.clients.iter().all(|c| c.ready.is_some()) {
                done_at = Some(step);
                break;
            }
            world.advance(Duration::from_millis(250));
        }
        assert!(
            done_at.is_some(),
            "seed {seed}: no relay path for both after ten minutes ({:?}, {:?})",
            world.clients[0].ready,
            world.clients[1].ready
        );
        // Both are on the endpoint the server holds for them, from their
        // own addresses.
        let vni = world.clients[0].ready.unwrap().vni;
        assert_eq!(world.clients[1].ready.unwrap().vni, vni, "seed {seed}");
        let endpoint = world
            .server
            .endpoints
            .iter()
            .find(|e| e.vni == vni)
            .unwrap();
        assert!(endpoint.bound.iter().all(Option::is_some), "seed {seed}");
    }
}

/// Keys as a real node has them still order into the pair the server keeps.
#[test]
fn the_pair_of_keys_is_ordered_whoever_asks() {
    let a = DiscoPublic(PrivateKey::generate().public());
    let b = DiscoPublic(PrivateKey::generate().public());
    assert_eq!(pair(a, b), pair(b, a));
    assert!(pair(a, b)[0].0 <= pair(a, b)[1].0);
}
