//! DERP, sans-IO: the relay protocol's frames and handshake. A client is
//! addressed by its node key; payloads are raw WireGuard or disco packets.
//!
//! Frames are `type:u8 ‖ len:u32 BE ‖ payload`. After the HTTP upgrade the
//! server sends its key, the client answers with a sealed `ClientInfo`, and
//! the server confirms with a sealed `ServerInfo`.

use crate::keys::{NodePublic, PrivateKey, PublicKey};
use crate::nacl::SharedBox;

pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
pub const PROTOCOL_VERSION: u32 = 2;
pub const HEADER_LEN: usize = 5;
pub const MAX_PACKET: usize = 64 << 10;
const MAX_FRAME: usize = 1 << 20;

pub const SERVER_KEY: u8 = 0x01;
pub const CLIENT_INFO: u8 = 0x02;
pub const SERVER_INFO: u8 = 0x03;
pub const SEND_PACKET: u8 = 0x04;
pub const RECV_PACKET: u8 = 0x05;
pub const KEEP_ALIVE: u8 = 0x06;
pub const NOTE_PREFERRED: u8 = 0x07;
pub const PEER_GONE: u8 = 0x08;
pub const PING: u8 = 0x12;
pub const PONG: u8 = 0x13;
pub const HEALTH: u8 = 0x14;
pub const RESTARTING: u8 = 0x15;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DerpError {
    #[error("malformed DERP frame")]
    Malformed,
    #[error("DERP frame too large")]
    TooLarge,
    #[error("unexpected DERP frame {0:#04x} during the handshake")]
    Unexpected(u8),
    #[error("could not open the DERP server's info")]
    Crypto,
}

/// A frame from the server, after the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A packet from `from`.
    Packet { from: NodePublic, data: Vec<u8> },
    /// Answer with a pong carrying the same bytes.
    Ping([u8; 8]),
    /// `peer` is not (or no longer) connected to this server.
    PeerGone(NodePublic),
    /// The server is restarting; reconnect.
    Restarting,
    /// A keepalive, health note or anything else to ignore.
    Other,
}

/// Encode one frame.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Take one complete frame off the front of `buf`: `(type, payload)`.
pub fn take_frame(buf: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, DerpError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let len = u32::from_be_bytes(buf[1..5].try_into().expect("4")) as usize;
    if len > MAX_FRAME {
        return Err(DerpError::TooLarge);
    }
    if buf.len() < HEADER_LEN + len {
        return Ok(None);
    }
    let kind = buf[0];
    let payload = buf[HEADER_LEN..HEADER_LEN + len].to_vec();
    buf.drain(..HEADER_LEN + len);
    Ok(Some((kind, payload)))
}

/// The server's key from its first frame.
pub fn parse_server_key(kind: u8, payload: &[u8]) -> Result<PublicKey, DerpError> {
    if kind != SERVER_KEY {
        return Err(DerpError::Unexpected(kind));
    }
    if payload.len() < 40 || &payload[..8] != MAGIC {
        return Err(DerpError::Malformed);
    }
    Ok(PublicKey(payload[8..40].try_into().expect("32")))
}

/// Our `ClientInfo` frame, sealed to the server's key with our node key.
pub fn client_info(node: &PrivateKey, server: &PublicKey) -> Vec<u8> {
    let info = serde_json::json!({ "version": PROTOCOL_VERSION, "CanAckPings": true });
    let sealed = SharedBox::new(node, server).seal(info.to_string().as_bytes());
    let mut payload = node.public().0.to_vec();
    payload.extend_from_slice(&sealed);
    frame(CLIENT_INFO, &payload)
}

/// Check the server's `ServerInfo` (it proves the server holds its key).
pub fn check_server_info(
    node: &PrivateKey,
    server: &PublicKey,
    kind: u8,
    payload: &[u8],
) -> Result<(), DerpError> {
    if kind != SERVER_INFO {
        return Err(DerpError::Unexpected(kind));
    }
    SharedBox::new(node, server)
        .open(payload)
        .map_err(|_| DerpError::Crypto)?;
    Ok(())
}

pub fn send_packet(to: &NodePublic, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + data.len());
    payload.extend_from_slice(&to.0 .0);
    payload.extend_from_slice(data);
    frame(SEND_PACKET, &payload)
}

pub fn note_preferred(home: bool) -> Vec<u8> {
    frame(NOTE_PREFERRED, &[home as u8])
}

pub fn pong(data: &[u8; 8]) -> Vec<u8> {
    frame(PONG, data)
}

/// Interpret a frame received after the handshake.
pub fn parse_event(kind: u8, payload: Vec<u8>) -> Result<Event, DerpError> {
    Ok(match kind {
        RECV_PACKET => {
            if payload.len() < 32 {
                return Err(DerpError::Malformed);
            }
            let from = NodePublic(PublicKey(payload[..32].try_into().expect("32")));
            Event::Packet {
                from,
                data: payload[32..].to_vec(),
            }
        }
        PING => Event::Ping(
            payload
                .get(..8)
                .ok_or(DerpError::Malformed)?
                .try_into()
                .expect("8"),
        ),
        PEER_GONE => {
            let key = payload.get(..32).ok_or(DerpError::Malformed)?;
            Event::PeerGone(NodePublic(PublicKey(key.try_into().expect("32"))))
        }
        RESTARTING => Event::Restarting,
        _ => Event::Other,
    })
}

/// The HTTP upgrade request that opens a DERP connection.
pub fn upgrade_request(host: &str) -> String {
    format!(
        "GET /derp HTTP/1.1\r\nHost: {host}\r\nUser-Agent: arkitekt-mesh\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_wait_for_bytes() {
        let f = frame(PING, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&f[..5], &[PING, 0, 0, 0, 8]);
        let mut partial = f[..7].to_vec();
        assert_eq!(take_frame(&mut partial).unwrap(), None);
        let mut buf = f.clone();
        buf.extend_from_slice(&frame(KEEP_ALIVE, &[]));
        let (kind, payload) = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(
            parse_event(kind, payload).unwrap(),
            Event::Ping([1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(take_frame(&mut buf).unwrap(), Some((KEEP_ALIVE, vec![])));
        assert!(buf.is_empty());
    }

    #[test]
    fn handshake_as_a_server_sees_it() {
        let node = PrivateKey::generate();
        let server = PrivateKey::generate();
        let mut key_frame = MAGIC.to_vec();
        key_frame.extend_from_slice(&server.public().0);
        let server_pub = parse_server_key(SERVER_KEY, &key_frame).unwrap();

        let mut info = client_info(&node, &server_pub);
        let (kind, payload) = take_frame(&mut info).unwrap().unwrap();
        assert_eq!(kind, CLIENT_INFO);
        let client = PublicKey(payload[..32].try_into().unwrap());
        assert_eq!(client, node.public());
        let json = SharedBox::new(&server, &client)
            .open(&payload[32..])
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json["version"], 2);

        let reply = SharedBox::new(&server, &client).seal(br#"{"version":2}"#);
        check_server_info(&node, &server_pub, SERVER_INFO, &reply).unwrap();
    }

    #[test]
    fn packets_carry_the_peer_key() {
        let peer = NodePublic(PrivateKey::generate().public());
        let mut f = send_packet(&peer, b"wg");
        let (kind, payload) = take_frame(&mut f).unwrap().unwrap();
        assert_eq!(kind, SEND_PACKET);
        // A server relays it as RecvPacket with the sender's key in front.
        match parse_event(RECV_PACKET, payload).unwrap() {
            Event::Packet { from, data } => {
                assert_eq!(from, peer);
                assert_eq!(data, b"wg");
            }
            other => panic!("{other:?}"),
        }
    }
}
