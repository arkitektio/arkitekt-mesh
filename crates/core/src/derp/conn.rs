//! One DERP connection without I/O: the HTTP upgrade (or none, when the
//! driver made a WebSocket's), the handshake, pings answered, the quiet
//! limit, and the server's frames as [`Event`]s. A driver moves the bytes
//! over its TLS stream (or WebSocket messages) and paces what it sends.
//!
//! Reconnecting is the driver's, with [`Backoff`].

use alloc::collections::VecDeque;

#[allow(unused_imports)]
use crate::prelude::*;

use super::{DerpError, Event};
use crate::control::http1::{self, Http1Error};
use crate::keys::{NodePublic, PrivateKey, PublicKey};
use crate::time::{Duration, Instant};

/// Servers send a keepalive every minute; after this long without any
/// frame the connection is presumed dead.
pub const QUIET_LIMIT: Duration = Duration::from_secs(120);

/// The subprotocol of the WebSocket form (`GET /derp`).
pub const WEBSOCKET_PROTOCOL: &str = "derp";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnError {
    #[error("DERP: {0}")]
    Http1(#[from] Http1Error),
    #[error("DERP: the upgrade failed with HTTP {0}")]
    Upgrade(u16),
    #[error("DERP: {0}")]
    Derp(#[from] DerpError),
    #[error("DERP: the server is restarting")]
    Restarting,
    #[error("DERP: the connection went quiet")]
    Quiet,
}

enum Phase {
    /// The upgrade request is out; its 101 comes first.
    Upgrading,
    /// Waiting for the server's key.
    ServerKey,
    /// Our info is out; waiting for the server's.
    ServerInfo(PublicKey),
    Up,
    Failed,
}

/// See the module docs.
pub struct DerpConn {
    node_key: PrivateKey,
    home: bool,
    phase: Phase,
    /// Bytes not yet a whole frame (or head).
    buf: Vec<u8>,
    out: Vec<u8>,
    events: VecDeque<Event>,
    /// When the server last sent anything.
    heard: Instant,
}

impl DerpConn {
    /// A connection to the DERP server at `authority` (its Host); the
    /// upgrade request is queued. `home`: tell the server it is our home.
    pub fn new(authority: &str, node_key: PrivateKey, home: bool, now: Instant) -> Self {
        let mut conn = Self::upgraded(node_key, home, now);
        conn.phase = Phase::Upgrading;
        conn.out = super::upgrade_request(authority).into_bytes();
        conn
    }

    /// A connection whose upgrade the driver made: the WebSocket form, a
    /// `GET /derp` with the [`WEBSOCKET_PROTOCOL`] subprotocol (a browser's
    /// WebSocket). The messages' bytes go to
    /// [`handle_input`](Self::handle_input), what
    /// [`poll_transmit`](Self::poll_transmit) gives goes out as binary messages.
    pub fn upgraded(node_key: PrivateKey, home: bool, now: Instant) -> Self {
        Self {
            node_key,
            home,
            phase: Phase::ServerKey,
            buf: Vec::new(),
            out: Vec::new(),
            events: VecDeque::new(),
            heard: now,
        }
    }

    /// Whether the handshake is done (packets may go out).
    pub fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up)
    }

    /// Queue a packet for `to` (dropped unless [`is_up`](Self::is_up)).
    pub fn send_packet(&mut self, to: &NodePublic, data: &[u8]) {
        if self.is_up() {
            self.out.extend_from_slice(&super::send_packet(to, data));
        }
    }

    /// Bytes from the server, in any slicing.
    pub fn handle_input(&mut self, now: Instant, data: &[u8]) -> Result<(), ConnError> {
        let result = self.input(now, data);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    /// The quiet limit: call when [`poll_timeout`](Self::poll_timeout) is due.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), ConnError> {
        if now >= self.poll_timeout() {
            self.phase = Phase::Failed;
            return Err(ConnError::Quiet);
        }
        Ok(())
    }

    /// When the connection is presumed dead, unless the server is heard.
    pub fn poll_timeout(&self) -> Instant {
        self.heard + QUIET_LIMIT
    }

    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        (!self.out.is_empty()).then(|| core::mem::take(&mut self.out))
    }

    /// A server frame: packets, peers gone, keepalives and the like
    /// ([`Event::Ping`] and [`Event::Restarting`] are handled here).
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn input(&mut self, now: Instant, data: &[u8]) -> Result<(), ConnError> {
        if matches!(self.phase, Phase::Failed) {
            return Err(ConnError::Quiet);
        }
        self.buf.extend_from_slice(data);
        self.heard = now;
        if matches!(self.phase, Phase::Upgrading) {
            let Some((head, used)) = http1::parse_head(&self.buf)? else {
                return Ok(());
            };
            if head.status != 101 {
                return Err(ConnError::Upgrade(head.status));
            }
            self.buf.drain(..used);
            self.phase = Phase::ServerKey;
        }
        while let Some((kind, payload)) = super::take_frame(&mut self.buf)? {
            match self.phase {
                Phase::ServerKey => {
                    let server = super::parse_server_key(kind, &payload)?;
                    self.out
                        .extend_from_slice(&super::client_info(&self.node_key, &server));
                    self.phase = Phase::ServerInfo(server);
                }
                Phase::ServerInfo(server) => {
                    super::check_server_info(&self.node_key, &server, kind, &payload)?;
                    if self.home {
                        self.out.extend_from_slice(&super::note_preferred(true));
                    }
                    self.phase = Phase::Up;
                }
                Phase::Up => match super::parse_event(kind, payload)? {
                    Event::Ping(data) => self.out.extend_from_slice(&super::pong(&data)),
                    Event::Restarting => return Err(ConnError::Restarting),
                    event => self.events.push_back(event),
                },
                Phase::Upgrading | Phase::Failed => unreachable!("handled above"),
            }
        }
        if self.buf.is_empty() && self.buf.capacity() > 64 << 10 {
            // A large packet passed: give its buffer back.
            self.buf = Vec::new();
        }
        Ok(())
    }
}

/// Reconnect delays: 100 ms, doubling, at most 5 s; reset once connected.
#[derive(Debug, Clone)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: Duration::from_millis(100),
        }
    }
}

impl Backoff {
    /// The delay before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(Duration::from_secs(5));
        delay
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::super::{frame, MAGIC, SERVER_INFO, SERVER_KEY};
    use super::*;
    use crate::nacl::SharedBox;

    /// The server's side of the handshake, enough for a test.
    struct Server {
        key: PrivateKey,
    }

    impl Server {
        fn hello(&self) -> Vec<u8> {
            let mut payload = MAGIC.to_vec();
            payload.extend_from_slice(&self.key.public().0);
            frame(SERVER_KEY, &payload)
        }

        /// Read the client's info; answer with our sealed info.
        fn info(&self, client_info: &[u8], client: &PublicKey) -> Vec<u8> {
            assert_eq!(client_info[0], super::super::CLIENT_INFO);
            let sealed = SharedBox::new(&self.key, client).seal(b"{}");
            frame(SERVER_INFO, &sealed)
        }
    }

    fn up(conn: &mut DerpConn, server: &Server, client: &PublicKey, now: Instant) {
        conn.handle_input(now, &server.hello()).unwrap();
        let info = conn.poll_transmit().unwrap();
        conn.handle_input(now, &server.info(&info, client)).unwrap();
        assert!(conn.is_up());
    }

    #[test]
    fn upgrade_handshake_and_frames_in_any_slicing() {
        let server = Server {
            key: PrivateKey::generate(),
        };
        let node = PrivateKey::generate();
        let now = Instant::from_micros(0);
        let mut conn = DerpConn::new("derp.example:8443", node.clone(), true, now);
        let request = String::from_utf8(conn.poll_transmit().unwrap()).unwrap();
        assert!(request.starts_with("GET /derp HTTP/1.1\r\nHost: derp.example:8443\r\n"));

        let mut wire = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n".to_vec();
        wire.extend(server.hello());
        for b in wire.chunks(3) {
            conn.handle_input(now, b).unwrap();
        }
        let info = conn.poll_transmit().unwrap();
        let reply = server.info(&info, &node.public());
        for b in reply.chunks(5) {
            conn.handle_input(now, b).unwrap();
        }
        assert!(conn.is_up());
        // Home: the preferred note follows the handshake.
        assert_eq!(
            conn.poll_transmit().unwrap(),
            super::super::note_preferred(true)
        );

        // A packet in, a ping answered, a keepalive passed on.
        let from = NodePublic(PrivateKey::generate().public());
        let mut packet = from.0 .0.to_vec();
        packet.extend_from_slice(b"wg");
        let mut wire = frame(super::super::RECV_PACKET, &packet);
        wire.extend(frame(super::super::PING, b"12345678"));
        wire.extend(frame(super::super::KEEP_ALIVE, &[]));
        for b in wire.chunks(2) {
            conn.handle_input(now, b).unwrap();
        }
        assert_eq!(
            conn.poll_event(),
            Some(Event::Packet {
                from,
                data: b"wg".to_vec()
            })
        );
        assert_eq!(conn.poll_event(), Some(Event::Other));
        assert_eq!(
            conn.poll_transmit().unwrap(),
            super::super::pong(b"12345678")
        );
    }

    #[test]
    fn websocket_form_quiet_limit_and_restarting() {
        let server = Server {
            key: PrivateKey::generate(),
        };
        let node = PrivateKey::generate();
        let start = Instant::from_micros(0);
        let mut conn = DerpConn::upgraded(node.clone(), false, start);
        assert_eq!(conn.poll_transmit(), None);
        up(&mut conn, &server, &node.public(), start);
        // Not home: nothing more to send. Packets go out once up.
        assert_eq!(conn.poll_transmit(), None);
        let to = NodePublic(PrivateKey::generate().public());
        conn.send_packet(&to, b"x");
        assert_eq!(
            conn.poll_transmit().unwrap(),
            super::super::send_packet(&to, b"x")
        );

        // Heard at 100 s: quiet until 220 s.
        let later = start + Duration::from_secs(100);
        conn.handle_input(later, &frame(super::super::KEEP_ALIVE, &[]))
            .unwrap();
        assert_eq!(conn.poll_timeout(), later + QUIET_LIMIT);
        conn.handle_timeout(later + Duration::from_secs(119))
            .unwrap();
        assert_eq!(
            conn.handle_timeout(later + QUIET_LIMIT),
            Err(ConnError::Quiet)
        );

        let mut conn = DerpConn::upgraded(node.clone(), false, start);
        up(&mut conn, &server, &node.public(), start);
        assert_eq!(
            conn.handle_input(start, &frame(super::super::RESTARTING, &[0; 8])),
            Err(ConnError::Restarting)
        );
    }

    #[test]
    fn a_refused_upgrade_and_a_wrong_first_frame() {
        let now = Instant::from_micros(0);
        let mut conn = DerpConn::new("d", PrivateKey::generate(), false, now);
        assert_eq!(
            conn.handle_input(now, b"HTTP/1.1 404 Not Found\r\n\r\n"),
            Err(ConnError::Upgrade(404))
        );
        let mut conn = DerpConn::upgraded(PrivateKey::generate(), false, now);
        assert!(conn
            .handle_input(now, &frame(super::super::KEEP_ALIVE, &[]))
            .is_err());
    }

    #[test]
    fn backoff_doubles_to_five_seconds() {
        let mut b = Backoff::default();
        let delays: Vec<u64> = (0..8).map(|_| b.next_delay().as_millis() as u64).collect();
        assert_eq!(delays, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }
}
