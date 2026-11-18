//! The relay as a client meets it: every message sealed and under its
//! Geneve header, as it comes off the socket.

use super::*;
use crate::geneve::Header;

struct Client {
    key: PrivateKey,
    addr: SocketAddr,
}

impl Client {
    fn new(addr: &str) -> Self {
        Self {
            key: PrivateKey::generate(),
            addr: addr.parse().unwrap(),
        }
    }

    fn disco(&self) -> DiscoPublic {
        DiscoPublic(self.key.public())
    }

    /// `msg` to the relay under `vni`, with the control bit, from `src`.
    fn control(
        &self,
        relay: &mut RelayServer,
        vni: u32,
        msg: &Message,
        src: SocketAddr,
        now: Instant,
    ) -> Option<(SocketAddr, Message)> {
        let header = Header {
            protocol: Protocol::Disco,
            vni,
            control: true,
        };
        let datagram = header.wrap(&disco::seal(&self.key, &relay.disco(), msg));
        let (to, reply) = relay.handle_datagram(src, &datagram, now)?;
        let (reply_header, payload) = geneve::unwrap(&reply).expect("a reply under Geneve");
        assert_eq!(reply_header, header, "the reply under the same header");
        let (from, msg) = disco::open(&self.key, payload).expect("sealed to the client");
        assert_eq!(from, relay.disco());
        Some((to, msg))
    }

    fn bind_msg(
        &self,
        endpoint: &RelayEndpoint,
        generation: u32,
        challenge: [u8; 32],
    ) -> RelayBind {
        let remote = *endpoint
            .clients
            .iter()
            .find(|c| **c != self.disco())
            .unwrap();
        RelayBind {
            vni: endpoint.vni,
            generation,
            remote,
            challenge,
        }
    }

    /// The whole handshake from `src`: bind, challenge, answer.
    fn bind_from(
        &self,
        relay: &mut RelayServer,
        endpoint: &RelayEndpoint,
        src: SocketAddr,
        now: Instant,
    ) {
        let bind = Message::RelayBind(self.bind_msg(endpoint, 7, [0; 32]));
        let (to, challenge) = self
            .control(relay, endpoint.vni, &bind, src, now)
            .expect("a challenge");
        assert_eq!(to, src);
        let Message::RelayChallenge(challenge) = challenge else {
            panic!("not a challenge: {challenge:?}");
        };
        let answer = Message::RelayAnswer(challenge);
        assert!(
            self.control(relay, endpoint.vni, &answer, src, now)
                .is_none(),
            "an answer gets no reply"
        );
    }

    fn bind(&self, relay: &mut RelayServer, endpoint: &RelayEndpoint, now: Instant) {
        self.bind_from(relay, endpoint, self.addr, now);
    }
}

fn at(secs: u64) -> Instant {
    Instant::from_micros(secs * 1_000_000)
}

/// A data packet under `vni`: WireGuard's shape, `tag` inside.
fn data(vni: u32, tag: u8) -> Vec<u8> {
    Header {
        protocol: Protocol::WireGuard,
        vni,
        control: false,
    }
    .wrap(&[4, 0, 0, 0, tag, tag, tag, tag])
}

fn relay() -> RelayServer {
    let mut relay = RelayServer::new();
    relay.set_addrs(vec!["198.51.100.1:40000".parse().unwrap()]);
    relay
}

fn bound_of(relay: &RelayServer, vni: u32) -> [Option<SocketAddr>; 2] {
    relay
        .sessions()
        .iter()
        .find(|s| s.vni == vni)
        .unwrap()
        .bound
}

/// Two peers get one endpoint, whoever asks and in whichever order; another
/// pair gets another; and nothing is given out before the relay knows where
/// it is, or for a pair that is none.
#[test]
fn a_pair_of_peers_has_one_endpoint() {
    let (a, b, c) = (
        Client::new("192.0.2.1:1"),
        Client::new("192.0.2.2:2"),
        Client::new("192.0.2.3:3"),
    );
    let mut homeless = RelayServer::new();
    assert_eq!(
        homeless.allocate(a.disco(), b.disco(), at(0)),
        Err(Refused::NotReady)
    );

    let mut relay = relay();
    let first = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    assert_eq!(first.server, relay.disco());
    assert_eq!(first.addrs, relay.addrs());
    assert_eq!(
        (first.bind_lifetime, first.steady_state_lifetime),
        (BIND_LIFETIME, STEADY_STATE_LIFETIME)
    );
    assert!(first.vni >= 1 && first.vni <= VNI_MAX);
    assert!(first.clients.contains(&a.disco()) && first.clients.contains(&b.disco()));
    assert!(
        first.clients[0].0 <= first.clients[1].0,
        "in the order clients compare them in"
    );
    // Asked again, by the other and the other way round: the same.
    assert_eq!(relay.allocate(b.disco(), a.disco(), at(5)).unwrap(), first);

    let second = relay.allocate(a.disco(), c.disco(), at(5)).unwrap();
    assert_ne!(second.vni, first.vni);
    assert!(second.lamport_id > first.lamport_id);
    assert_eq!(relay.sessions().len(), 2);

    assert_eq!(
        relay.allocate(a.disco(), a.disco(), at(5)),
        Err(Refused::BadPair)
    );
    assert_eq!(
        relay.allocate(a.disco(), relay.disco(), at(5)),
        Err(Refused::BadPair)
    );
}

/// Once both have bound, what the one sends under the VNI reaches the
/// other's address unchanged; before that, and from anywhere else, nothing.
#[test]
fn bound_peers_have_their_packets_forwarded() {
    let (a, b) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
    );
    let mut relay = relay();
    let endpoint = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    let packet = data(endpoint.vni, 0xaa);

    assert_eq!(
        relay.handle_datagram(a.addr, &packet, at(1)),
        None,
        "nobody bound"
    );
    a.bind(&mut relay, &endpoint, at(1));
    assert_eq!(
        relay.handle_datagram(a.addr, &packet, at(1)),
        None,
        "the other not bound"
    );
    b.bind(&mut relay, &endpoint, at(2));

    assert_eq!(
        relay.handle_datagram(a.addr, &packet, at(3)),
        Some((b.addr, packet.clone()))
    );
    let back = data(endpoint.vni, 0xbb);
    assert_eq!(
        relay.handle_datagram(b.addr, &back, at(3)),
        Some((a.addr, back.clone()))
    );
    // Disco between the peers is forwarded the same way: not opened.
    let ping = Header {
        protocol: Protocol::Disco,
        vni: endpoint.vni,
        control: false,
    }
    .wrap(&disco::seal(
        &a.key,
        &b.disco(),
        &Message::Ping {
            tx: [1; 12],
            node_key: None,
        },
    ));
    assert_eq!(
        relay.handle_datagram(a.addr, &ping, at(3)),
        Some((b.addr, ping.clone()))
    );

    // From an address nobody bound from, or under another VNI: dropped.
    let elsewhere: SocketAddr = "192.0.2.1:1001".parse().unwrap();
    assert_eq!(relay.handle_datagram(elsewhere, &packet, at(3)), None);
    assert_eq!(
        relay.handle_datagram(a.addr, &data(endpoint.vni + 1, 1), at(3)),
        None
    );

    let session = relay.sessions()[0];
    let ai = session
        .clients
        .iter()
        .position(|c| *c == a.disco())
        .unwrap();
    assert_eq!(session.packets[ai], 2);
    assert_eq!(session.packets[1 - ai], 1);
    assert_eq!(session.bytes[1 - ai], back.len() as u64);
}

/// A bind is answered only for this endpoint's two keys, and bound only by
/// the challenge echoed from where it was sent to.
#[test]
fn only_the_challenged_address_is_bound() {
    let (a, b, stranger) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
        Client::new("198.51.100.9:9"),
    );
    let mut relay = relay();
    let endpoint = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    let vni = endpoint.vni;
    let bind = |generation: u32| Message::RelayBind(a.bind_msg(&endpoint, generation, [0; 32]));

    // Not one of the two; generation 0; the wrong peer named; the wrong VNI sealed.
    let theirs = Message::RelayBind(RelayBind {
        vni,
        generation: 1,
        remote: b.disco(),
        challenge: [0; 32],
    });
    assert!(stranger
        .control(&mut relay, vni, &theirs, stranger.addr, at(1))
        .is_none());
    assert!(a
        .control(&mut relay, vni, &bind(0), a.addr, at(1))
        .is_none());
    let misnamed = Message::RelayBind(RelayBind {
        remote: stranger.disco(),
        ..a.bind_msg(&endpoint, 1, [0; 32])
    });
    assert!(a
        .control(&mut relay, vni, &misnamed, a.addr, at(1))
        .is_none());
    let other_vni = Message::RelayBind(RelayBind {
        vni: vni + 1,
        ..a.bind_msg(&endpoint, 1, [0; 32])
    });
    assert!(a
        .control(&mut relay, vni, &other_vni, a.addr, at(1))
        .is_none());

    let (_, challenge) = a.control(&mut relay, vni, &bind(5), a.addr, at(1)).unwrap();
    let Message::RelayChallenge(challenge) = challenge else {
        panic!()
    };
    assert_eq!(
        (challenge.vni, challenge.generation, challenge.remote),
        (vni, 5, b.disco())
    );
    assert_ne!(challenge.challenge, [0; 32]);

    // The answer from another address (a forged source could not have read
    // the challenge, and one who read it elsewhere is not where it says).
    let elsewhere: SocketAddr = "192.0.2.77:1000".parse().unwrap();
    let answer = Message::RelayAnswer(challenge.clone());
    a.control(&mut relay, vni, &answer, elsewhere, at(1));
    // A challenge made up, and one for another handshake's generation.
    let made_up = Message::RelayAnswer(RelayBind {
        challenge: [9; 32],
        ..challenge.clone()
    });
    a.control(&mut relay, vni, &made_up, a.addr, at(1));
    let other = Message::RelayAnswer(RelayBind {
        generation: 6,
        ..challenge.clone()
    });
    a.control(&mut relay, vni, &other, a.addr, at(1));
    assert_eq!(bound_of(&relay, vni), [None, None]);

    a.control(&mut relay, vni, &answer, a.addr, at(1));
    assert!(bound_of(&relay, vni).contains(&Some(a.addr)));
    // That handshake is over: its answer does not bind again from elsewhere.
    a.control(
        &mut relay,
        vni,
        &Message::RelayAnswer(challenge),
        elsewhere,
        at(1),
    );
    assert!(!bound_of(&relay, vni).contains(&Some(elsewhere)));
}

/// A peer that moved binds again, and its packets are taken from the new
/// address only.
#[test]
fn a_new_handshake_moves_a_peer() {
    let (a, b) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
    );
    let mut relay = relay();
    let endpoint = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    a.bind(&mut relay, &endpoint, at(1));
    b.bind(&mut relay, &endpoint, at(1));
    let moved: SocketAddr = "192.0.2.50:5000".parse().unwrap();
    a.bind_from(&mut relay, &endpoint, moved, at(10));
    let packet = data(endpoint.vni, 1);
    assert_eq!(
        relay.handle_datagram(a.addr, &packet, at(11)),
        None,
        "the old address"
    );
    assert_eq!(
        relay.handle_datagram(moved, &packet, at(11)),
        Some((b.addr, packet.clone()))
    );
    assert_eq!(
        relay.handle_datagram(b.addr, &packet, at(11)),
        Some((moved, packet))
    );
}

/// A challenge is good while its secret, or the one after it, is the
/// relay's: at least two minutes, at most four.
#[test]
fn challenges_outlive_one_rotation_of_the_secret() {
    let (a, b) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
    );
    for (answered_after, binds) in [(100, true), (130, true), (250, false)] {
        let mut relay = relay();
        let endpoint = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
        // Keep the endpoint alive past its bind lifetime: the other binds
        // and both stay heard of.
        let bind = Message::RelayBind(a.bind_msg(&endpoint, 3, [0; 32]));
        let (_, challenge) = a
            .control(&mut relay, endpoint.vni, &bind, a.addr, at(0))
            .unwrap();
        let Message::RelayChallenge(challenge) = challenge else {
            panic!()
        };
        let later = at(answered_after);
        a.control(
            &mut relay,
            endpoint.vni,
            &Message::RelayAnswer(challenge),
            a.addr,
            later,
        );
        let bound = bound_of(&relay, endpoint.vni).contains(&Some(a.addr));
        assert_eq!(bound, binds, "answered after {answered_after} s");
    }
}

/// An endpoint both do not bind to goes after 30 s, a bound one after five
/// minutes of either side's silence; the pair then gets a new one, later by
/// its Lamport id.
#[test]
fn endpoints_expire_unbound_or_silent() {
    let (a, b) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
    );
    let mut relay = relay();
    let first = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    a.bind(&mut relay, &first, at(1));
    relay.expire(at(30));
    assert_eq!(relay.sessions().len(), 1);
    relay.expire(at(31));
    assert!(relay.sessions().is_empty(), "one never bound");
    assert_eq!(
        relay.handle_datagram(a.addr, &data(first.vni, 1), at(31)),
        None
    );

    let second = relay.allocate(a.disco(), b.disco(), at(40)).unwrap();
    assert!(second.lamport_id > first.lamport_id);
    a.bind(&mut relay, &second, at(41));
    b.bind(&mut relay, &second, at(41));
    // One side keeps sending; the other went quiet.
    let packet = data(second.vni, 1);
    for t in (60..=340).step_by(20) {
        assert!(
            relay.handle_datagram(a.addr, &packet, at(t)).is_some(),
            "at {t} s"
        );
        relay.expire(at(t));
    }
    assert_eq!(
        relay.sessions().len(),
        1,
        "within five minutes of the quiet side"
    );
    relay.expire(at(342));
    assert!(relay.sessions().is_empty());
    // Asking allocates anew, and expires what is due on the way.
    let third = relay.allocate(a.disco(), b.disco(), at(350)).unwrap();
    assert!(third.lamport_id > second.lamport_id);
}

/// The table is bounded, and a VNI is not handed out twice.
#[test]
fn endpoints_are_bounded_and_vnis_distinct() {
    let mut relay = relay();
    relay.set_max_endpoints(8);
    let a = Client::new("192.0.2.1:1");
    let mut vnis = Vec::new();
    for i in 0..8u8 {
        let other = DiscoPublic(crate::keys::PublicKey([i + 1; 32]));
        vnis.push(relay.allocate(a.disco(), other, at(0)).unwrap().vni);
    }
    let unique: hashbrown::HashSet<u32> = vnis.iter().copied().collect();
    assert_eq!(unique.len(), 8);
    let ninth = DiscoPublic(crate::keys::PublicKey([99; 32]));
    assert_eq!(relay.allocate(a.disco(), ninth, at(0)), Err(Refused::Full));
    // Room again once they expire.
    assert!(relay.allocate(a.disco(), ninth, at(31)).is_ok());
    assert_eq!(relay.sessions().len(), 1);
}

/// Whatever arrives on the socket: nothing sent for it, no state, no panic.
#[test]
fn noise_on_the_socket_is_dropped() {
    let (a, b) = (
        Client::new("192.0.2.1:1000"),
        Client::new("203.0.113.2:2000"),
    );
    let mut relay = relay();
    let endpoint = relay.allocate(a.disco(), b.disco(), at(0)).unwrap();
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let good = Header {
        protocol: Protocol::Disco,
        vni: endpoint.vni,
        control: true,
    }
    .wrap(&disco::seal(
        &a.key,
        &relay.disco(),
        &Message::RelayBind(a.bind_msg(&endpoint, 1, [0; 32])),
    ));
    for round in 0..5000 {
        // Random bytes, and a real bind with a byte or its length changed.
        let datagram: Vec<u8> = if round % 2 == 0 {
            (0..next() % 200).map(|_| next() as u8).collect()
        } else {
            let mut bent = good.clone();
            let at = (next() as usize) % bent.len();
            bent[at] ^= 1 + (next() as u8 % 255);
            bent.truncate(bent.len() - (next() as usize % 3));
            bent
        };
        let reply = relay.handle_datagram(a.addr, &datagram, at(1));
        // Only a bind that still opens is answered: one whose changed byte
        // was in the header's reserved-for-us bits.
        if let Some((to, _)) = reply {
            assert_eq!(to, a.addr);
        }
    }
    assert_eq!(bound_of(&relay, endpoint.vni), [None, None]);
    assert_eq!(relay.sessions().len(), 1);
}
