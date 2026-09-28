//! Disco, sans-IO: the sealed ping/pong/call-me-maybe messages peers use to
//! find a direct UDP path.
//!
//! On the wire: `"TS💬" ‖ sender disco key(32) ‖ nacl box(type ‖ 0 ‖ payload)`.
//! Addresses are 16-byte IPs (IPv4 v4-mapped) plus a big-endian port.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::keys::{DiscoPublic, NodePublic, PrivateKey, PublicKey};
use crate::nacl::SharedBox;

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const HEADER_LEN: usize = MAGIC.len() + 32;

const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;

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
        }
        out
    }

    fn decode(plain: &[u8]) -> Option<Self> {
        let (&kind, rest) = plain.split_first()?;
        let (&_version, body) = rest.split_first()?;
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
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&ours.public().0);
    out.extend_from_slice(&SharedBox::new(ours, &to.0).seal(&msg.encode()));
    out
}

/// Open a disco packet addressed to us: `(sender, message)`.
pub fn open(ours: &PrivateKey, packet: &[u8]) -> Option<(DiscoPublic, Message)> {
    let from = sender(packet)?;
    let plain = SharedBox::new(ours, &from.0)
        .open(&packet[HEADER_LEN..])
        .ok()?;
    Some((from, Message::decode(&plain)?))
}

#[cfg(test)]
mod tests {
    use super::*;

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
