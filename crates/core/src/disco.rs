//! Disco, sans-IO: the sealed ping/pong/call-me-maybe messages peers use to
//! find a direct UDP path, and the ones that set up a path through a peer
//! relay (a node of the tailnet that forwards UDP for two others): allocate
//! an endpoint on it, tell the peer of it, bind to it.
//!
//! On the wire: `"TS💬" ‖ sender disco key(32) ‖ nacl box(type ‖ 0 ‖ payload)`.
//! Addresses are 16-byte IPs (IPv4 v4-mapped) plus a big-endian port.

#[allow(unused_imports)]
use crate::prelude::*;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};

use hashbrown::HashMap;

use crate::keys::{DiscoPublic, NodePublic, PrivateKey, PublicKey};
use crate::nacl::SharedBox;

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER_LEN: usize = MAGIC.len() + 32;

const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;
const RELAY_BIND: u8 = 0x04;
const RELAY_CHALLENGE: u8 = 0x05;
const RELAY_ANSWER: u8 = 0x06;
const CALL_ME_MAYBE_VIA: u8 = 0x07;
const RELAY_ALLOCATE: u8 = 0x08;
const RELAY_ALLOCATED: u8 = 0x09;

/// A bind message's length, and a relay endpoint's before its addresses.
const BIND_LEN: usize = 4 + 4 + 32 + 32;
const ENDPOINT_LEN: usize = 32 + 2 * 32 + 8 + 4 + 8 + 8;
const ADDR_LEN: usize = 18;
/// Addresses taken from one relay endpoint (a server has a handful).
const MAX_RELAY_ADDRS: usize = 16;

pub type TxId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping {
        tx: TxId,
        node_key: Option<NodePublic>,
    },
    Pong {
        tx: TxId,
        src: SocketAddr,
    },
    CallMeMaybe {
        endpoints: Vec<SocketAddr>,
    },
    /// To a relay server, in Geneve with the control bit: let me use this
    /// endpoint. The first of the three messages of the bind handshake.
    RelayBind(RelayBind),
    /// The relay server's answer: prove you hold the disco key, and that
    /// packets from where you send reach you.
    RelayChallenge(RelayBind),
    /// The challenge, echoed.
    RelayAnswer(RelayBind),
    /// Over DERP only: reach me through this relay endpoint (which the
    /// sender allocated for the two of us).
    CallMeMaybeVia(RelayEndpoint),
    /// Over DERP only, to a relay server: an endpoint for these two disco
    /// keys, please.
    AllocateRelay {
        clients: [DiscoPublic; 2],
        /// Echoed in the answer.
        generation: u32,
    },
    /// Over DERP only: the endpoint allocated.
    RelayAllocated {
        generation: u32,
        endpoint: RelayEndpoint,
    },
}

/// What the three messages of the bind handshake carry, all the same size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBind {
    /// The endpoint's VNI, sealed: it must be the Geneve header's.
    pub vni: u32,
    /// The handshake's number, new (and not zero) for each one.
    pub generation: u32,
    /// The disco key of the peer at the endpoint's other end.
    pub remote: DiscoPublic,
    /// The server's challenge and the client's echo of it; padding in the
    /// first message.
    pub challenge: [u8; 32],
}

/// An endpoint on a relay server, allocated for two disco keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// The server's disco key for the bind handshake: the same for its
    /// lifetime, and with `lamport_id` the endpoint's identity.
    pub server: DiscoPublic,
    /// The two peers that may bind to it.
    pub clients: [DiscoPublic; 2],
    /// Counts the server's allocations: of two descriptions of one server's
    /// endpoint, the higher is the later.
    pub lamport_id: u64,
    pub vni: u32,
    /// How long the server keeps the endpoint for both to bind.
    pub bind_lifetime: core::time::Duration,
    /// How long it keeps a bound endpoint without traffic both ways.
    pub steady_state_lifetime: core::time::Duration,
    /// Where the server may be reached.
    pub addrs: Vec<SocketAddr>,
}

impl RelayBind {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vni.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.remote.0 .0);
        out.extend_from_slice(&self.challenge);
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..BIND_LEN)?;
        Some(Self {
            vni: u32::from_be_bytes(b[..4].try_into().ok()?),
            generation: u32::from_be_bytes(b[4..8].try_into().ok()?),
            remote: disco_key(&b[8..40])?,
            challenge: b[40..72].try_into().ok()?,
        })
    }
}

impl RelayEndpoint {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.server.0 .0);
        for client in &self.clients {
            out.extend_from_slice(&client.0 .0);
        }
        out.extend_from_slice(&self.lamport_id.to_be_bytes());
        out.extend_from_slice(&self.vni.to_be_bytes());
        for lifetime in [self.bind_lifetime, self.steady_state_lifetime] {
            // Go's time.Duration: nanoseconds.
            let nanos = u64::try_from(lifetime.as_nanos()).unwrap_or(u64::MAX);
            out.extend_from_slice(&nanos.to_be_bytes());
        }
        for addr in &self.addrs {
            put_addr(out, addr);
        }
    }

    /// At least one address, and nothing left over.
    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ENDPOINT_LEN + ADDR_LEN || !(b.len() - ENDPOINT_LEN).is_multiple_of(ADDR_LEN) {
            return None;
        }
        let nanos = |at: usize| -> Option<core::time::Duration> {
            let nanos = u64::from_be_bytes(b[at..at + 8].try_into().ok()?);
            Some(core::time::Duration::from_nanos(nanos))
        };
        Some(Self {
            server: disco_key(&b[..32])?,
            clients: [disco_key(&b[32..64])?, disco_key(&b[64..96])?],
            lamport_id: u64::from_be_bytes(b[96..104].try_into().ok()?),
            vni: u32::from_be_bytes(b[104..108].try_into().ok()?),
            bind_lifetime: nanos(108)?,
            steady_state_lifetime: nanos(116)?,
            addrs: b[ENDPOINT_LEN..]
                .chunks(ADDR_LEN)
                .take(MAX_RELAY_ADDRS)
                .filter_map(get_addr)
                .collect(),
        })
    }
}

fn disco_key(b: &[u8]) -> Option<DiscoPublic> {
    Some(DiscoPublic(PublicKey(b.get(..32)?.try_into().ok()?)))
}

/// Whether `packet` is a disco packet (by its magic and length).
pub fn looks_like_disco(packet: &[u8]) -> bool {
    packet.len() >= HEADER_LEN + crate::nacl::OVERHEAD && packet.starts_with(MAGIC)
}

/// The sender's disco key, without opening the box.
pub fn sender(packet: &[u8]) -> Option<DiscoPublic> {
    looks_like_disco(packet).then(|| {
        DiscoPublic(PublicKey(
            packet[MAGIC.len()..HEADER_LEN].try_into().expect("32"),
        ))
    })
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Ping { tx, node_key } => {
                out.extend_from_slice(&[PING, 0]);
                out.extend_from_slice(tx);
                if let Some(key) = node_key {
                    out.extend_from_slice(&key.0 .0);
                }
            }
            Message::Pong { tx, src } => {
                out.extend_from_slice(&[PONG, 0]);
                out.extend_from_slice(tx);
                put_addr(&mut out, src);
            }
            Message::CallMeMaybe { endpoints } => {
                out.extend_from_slice(&[CALL_ME_MAYBE, 0]);
                for ep in endpoints {
                    put_addr(&mut out, ep);
                }
            }
            Message::RelayBind(bind) => {
                out.extend_from_slice(&[RELAY_BIND, 0]);
                bind.encode(&mut out);
            }
            Message::RelayChallenge(bind) => {
                out.extend_from_slice(&[RELAY_CHALLENGE, 0]);
                bind.encode(&mut out);
            }
            Message::RelayAnswer(bind) => {
                out.extend_from_slice(&[RELAY_ANSWER, 0]);
                bind.encode(&mut out);
            }
            Message::CallMeMaybeVia(endpoint) => {
                out.extend_from_slice(&[CALL_ME_MAYBE_VIA, 0]);
                endpoint.encode(&mut out);
            }
            Message::AllocateRelay {
                clients,
                generation,
            } => {
                out.extend_from_slice(&[RELAY_ALLOCATE, 0]);
                for client in clients {
                    out.extend_from_slice(&client.0 .0);
                }
                out.extend_from_slice(&generation.to_be_bytes());
            }
            Message::RelayAllocated {
                generation,
                endpoint,
            } => {
                out.extend_from_slice(&[RELAY_ALLOCATED, 0]);
                out.extend_from_slice(&generation.to_be_bytes());
                endpoint.encode(&mut out);
            }
        }
        out
    }

    fn decode(plain: &[u8]) -> Option<Self> {
        let (&kind, rest) = plain.split_first()?;
        let (&version, body) = rest.split_first()?;
        // The relay messages are read at the version we know only.
        if kind >= RELAY_BIND && version != 0 {
            return None;
        }
        match kind {
            PING => {
                let tx = body.get(..12)?.try_into().ok()?;
                let node_key = body
                    .get(12..44)
                    .map(|k| NodePublic(PublicKey(k.try_into().expect("32"))));
                Some(Message::Ping { tx, node_key })
            }
            PONG => {
                let tx = body.get(..12)?.try_into().ok()?;
                let src = get_addr(body.get(12..30)?)?;
                Some(Message::Pong { tx, src })
            }
            CALL_ME_MAYBE => {
                if body.len() % 18 != 0 {
                    return Some(Message::CallMeMaybe { endpoints: vec![] });
                }
                let endpoints = body.chunks(18).filter_map(get_addr).collect();
                Some(Message::CallMeMaybe { endpoints })
            }
            RELAY_BIND => RelayBind::decode(body).map(Message::RelayBind),
            RELAY_CHALLENGE => RelayBind::decode(body).map(Message::RelayChallenge),
            RELAY_ANSWER => RelayBind::decode(body).map(Message::RelayAnswer),
            CALL_ME_MAYBE_VIA => RelayEndpoint::decode(body).map(Message::CallMeMaybeVia),
            RELAY_ALLOCATE => Some(Message::AllocateRelay {
                clients: [disco_key(body)?, disco_key(body.get(32..)?)?],
                generation: u32::from_be_bytes(body.get(64..68)?.try_into().ok()?),
            }),
            RELAY_ALLOCATED => Some(Message::RelayAllocated {
                generation: u32::from_be_bytes(body.get(..4)?.try_into().ok()?),
                endpoint: RelayEndpoint::decode(&body[4..])?,
            }),
            _ => None,
        }
    }
}

fn put_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn get_addr(b: &[u8]) -> Option<SocketAddr> {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(b.get(..16)?).ok()?);
    let port = u16::from_be_bytes(b.get(16..18)?.try_into().ok()?);
    let ip = match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    };
    Some(SocketAddr::new(ip, port))
}

/// Seal `msg` from us to the peer with disco key `to`.
pub fn seal(ours: &PrivateKey, to: &DiscoPublic, msg: &Message) -> Vec<u8> {
    sealed(
        &DiscoPublic(ours.public()),
        &SharedBox::new(ours, &to.0),
        msg,
    )
}

/// Open a disco packet addressed to us: `(sender, message)`.
pub fn open(ours: &PrivateKey, packet: &[u8]) -> Option<(DiscoPublic, Message)> {
    let from = sender(packet)?;
    let message = opened(&SharedBox::new(ours, &from.0), packet)?;
    Some((from, message))
}

pub(crate) fn sealed(ours: &DiscoPublic, shared: &SharedBox, msg: &Message) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&ours.0 .0);
    out.extend_from_slice(&shared.seal(&msg.encode()));
    out
}

pub(crate) fn opened(shared: &SharedBox, packet: &[u8]) -> Option<Message> {
    Message::decode(&shared.open(&packet[HEADER_LEN..]).ok()?)
}

/// Peers' boxes kept at most; past that the cache starts over.
const BOXES: usize = 64;

/// Our disco key, with its public half and the box shared with each peer
/// computed once. Each is an X25519: on an ESP32-S3 about 18 ms, and a
/// ping answered with a pong took three of them.
pub struct DiscoKeys {
    pub(crate) private: PrivateKey,
    public: DiscoPublic,
    boxes: HashMap<DiscoPublic, SharedBox>,
}

impl DiscoKeys {
    pub fn new(private: PrivateKey) -> Self {
        Self {
            public: DiscoPublic(private.public()),
            private,
            boxes: HashMap::new(),
        }
    }

    pub fn public(&self) -> DiscoPublic {
        self.public
    }

    /// Seal `msg` from us to the peer with disco key `to`.
    pub fn seal(&mut self, to: &DiscoPublic, msg: &Message) -> Vec<u8> {
        let public = self.public;
        sealed(&public, self.shared(to), msg)
    }

    /// Open a packet from `from` (its [`sender`], already known to be a
    /// peer: only peers get a box kept).
    pub fn open(&mut self, from: &DiscoPublic, packet: &[u8]) -> Option<Message> {
        opened(self.shared(from), packet)
    }

    fn shared(&mut self, peer: &DiscoPublic) -> &SharedBox {
        if self.boxes.len() >= BOXES && !self.boxes.contains_key(peer) {
            self.boxes.clear();
        }
        let private = &self.private;
        self.boxes
            .entry(*peer)
            .or_insert_with(|| SharedBox::new(private, &peer.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_boxes_speak_with_fresh_ones_one_per_peer() {
        let a = PrivateKey::generate();
        let b = PrivateKey::generate();
        let b_public = DiscoPublic(b.public());
        let mut keys = DiscoKeys::new(a.clone());
        let ping = Message::Ping {
            tx: [7; 12],
            node_key: None,
        };
        let sealed = keys.seal(&b_public, &ping);
        assert_eq!(open(&b, &sealed), Some((keys.public(), ping)));

        let pong = Message::Pong {
            tx: [7; 12],
            src: "1.2.3.4:5".parse().unwrap(),
        };
        let answer = seal(&b, &keys.public(), &pong);
        assert_eq!(sender(&answer), Some(b_public));
        assert_eq!(keys.open(&b_public, &answer), Some(pong));
        assert_eq!(keys.boxes.len(), 1);
    }

    #[test]
    fn messages_round_trip() {
        let a = PrivateKey::generate();
        let b = PrivateKey::generate();
        let b_disco = DiscoPublic(b.public());
        let node = NodePublic(PrivateKey::generate().public());
        for msg in [
            Message::Ping {
                tx: [1; 12],
                node_key: Some(node),
            },
            Message::Pong {
                tx: [2; 12],
                src: "192.168.1.5:41641".parse().unwrap(),
            },
            Message::Pong {
                tx: [3; 12],
                src: "[2001:db8::1]:9".parse().unwrap(),
            },
            Message::CallMeMaybe {
                endpoints: vec!["1.2.3.4:5".parse().unwrap(), "[::1]:6".parse().unwrap()],
            },
        ] {
            let packet = seal(&a, &b_disco, &msg);
            assert!(looks_like_disco(&packet));
            assert!(!crate::wg::is_wireguard(&packet));
            assert_eq!(sender(&packet), Some(DiscoPublic(a.public())));
            assert_eq!(open(&b, &packet), Some((DiscoPublic(a.public()), msg)));
        }
    }

    /// The relay messages as tailscale's own marshalling writes them
    /// (tests/harness/vectors_test.go), both ways.
    #[test]
    fn relay_messages_are_tailscale_s() {
        let key = |fill: u8| DiscoPublic(PublicKey([fill; 32]));
        let bind = RelayBind {
            vni: 0x00ab_cdef,
            generation: 7,
            remote: key(0x22),
            challenge: core::array::from_fn(|i| 0x40 + i as u8),
        };
        let endpoint = RelayEndpoint {
            server: key(0x11),
            clients: [key(0x22), key(0x33)],
            lamport_id: 0x0102_0304_0506_0708,
            vni: 0x00ab_cdef,
            bind_lifetime: core::time::Duration::from_secs(30),
            steady_state_lifetime: core::time::Duration::from_secs(300),
            addrs: vec![
                "192.0.2.7:40000".parse().unwrap(),
                "[2001:db8::7]:40001".parse().unwrap(),
            ],
        };
        const COMMON: &str = "00abcdef00000007\
            2222222222222222222222222222222222222222222222222222222222222222\
            404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        const ENDPOINT: &str = "\
            1111111111111111111111111111111111111111111111111111111111111111\
            2222222222222222222222222222222222222222222222222222222222222222\
            3333333333333333333333333333333333333333333333333333333333333333\
            010203040506070800abcdef00000006fc23ac0000000045d964b800\
            00000000000000000000ffffc00002079c40\
            20010db80000000000000000000000079c41";
        let clients = "\
            2222222222222222222222222222222222222222222222222222222222222222\
            3333333333333333333333333333333333333333333333333333333333333333";
        for (msg, wire) in [
            (Message::RelayBind(bind.clone()), format!("0400{COMMON}")),
            (
                Message::RelayChallenge(bind.clone()),
                format!("0500{COMMON}"),
            ),
            (Message::RelayAnswer(bind), format!("0600{COMMON}")),
            (
                Message::CallMeMaybeVia(endpoint.clone()),
                format!("0700{ENDPOINT}"),
            ),
            (
                Message::AllocateRelay {
                    clients: [key(0x22), key(0x33)],
                    generation: 9,
                },
                format!("0800{clients}00000009"),
            ),
            (
                Message::RelayAllocated {
                    generation: 9,
                    endpoint,
                },
                format!("090000000009{ENDPOINT}"),
            ),
        ] {
            let wire: String = wire.split_whitespace().collect();
            assert_eq!(hex::encode(msg.encode()), wire, "{msg:?}");
            assert_eq!(Message::decode(&hex::decode(&wire).unwrap()), Some(msg));
        }
    }

    /// Cut short, grown by a byte, or of a version we do not know: not read,
    /// never a panic.
    #[test]
    fn malformed_relay_messages_are_not_read() {
        let key = DiscoPublic(PublicKey([9; 32]));
        let endpoint = RelayEndpoint {
            server: key,
            clients: [key, key],
            lamport_id: 1,
            vni: 2,
            bind_lifetime: core::time::Duration::from_secs(30),
            steady_state_lifetime: core::time::Duration::from_secs(300),
            addrs: vec!["192.0.2.7:1".parse().unwrap()],
        };
        let bind = RelayBind {
            vni: 2,
            generation: 1,
            remote: key,
            challenge: [0; 32],
        };
        for msg in [
            Message::RelayBind(bind),
            Message::CallMeMaybeVia(endpoint.clone()),
            Message::AllocateRelay {
                clients: [key, key],
                generation: 1,
            },
            Message::RelayAllocated {
                generation: 1,
                endpoint: endpoint.clone(),
            },
        ] {
            let wire = msg.encode();
            for cut in 0..wire.len() {
                assert_eq!(Message::decode(&wire[..cut]), None, "{msg:?} cut at {cut}");
            }
            let mut other_version = wire.clone();
            other_version[1] = 1;
            assert_eq!(Message::decode(&other_version), None);
        }
        // An endpoint needs an address, and whole ones.
        let mut bare = endpoint.clone();
        bare.addrs.clear();
        assert_eq!(
            Message::decode(&Message::CallMeMaybeVia(bare).encode()),
            None
        );
        let mut ragged = Message::CallMeMaybeVia(endpoint.clone()).encode();
        ragged.push(0);
        assert_eq!(Message::decode(&ragged), None);
        // More addresses than we keep are cut, not refused.
        let mut many = endpoint;
        many.addrs = (0..40u16)
            .map(|port| SocketAddr::from(([192, 0, 2, 7], port + 1)))
            .collect();
        let Some(Message::CallMeMaybeVia(read)) =
            Message::decode(&Message::CallMeMaybeVia(many).encode())
        else {
            panic!("not read");
        };
        assert_eq!(read.addrs.len(), MAX_RELAY_ADDRS);
    }

    #[test]
    fn ipv4_is_v4_mapped_on_the_wire() {
        let mut out = Vec::new();
        put_addr(&mut out, &"1.2.3.4:258".parse().unwrap());
        assert_eq!(&out[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&out[16..], &[1, 2]);
    }

    #[test]
    fn strangers_cannot_open() {
        let a = PrivateKey::generate();
        let b = PrivateKey::generate();
        let packet = seal(
            &a,
            &DiscoPublic(b.public()),
            &Message::CallMeMaybe { endpoints: vec![] },
        );
        assert_eq!(open(&PrivateKey::generate(), &packet), None);
    }
}
