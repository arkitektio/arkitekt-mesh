//! WireGuard, sans-IO: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshakes,
//! transport sessions with replay protection, and the protocol's timers.
//!
//! A [`Tunnel`] holds this node's static key and one [`Peer`] per remote
//! node key. Feed it IP packets to send ([`Tunnel::encapsulate`]),
//! datagrams received ([`Tunnel::decapsulate`]) and the passage of time
//! ([`Tunnel::tick`]); it answers with datagrams to send to a peer and IP
//! packets that arrived. Which path a datagram takes (UDP or DERP) is not its
//! concern.
//!
//! As in Tailscale, the preshared key is all zeros and a peer's WireGuard
//! public key is its node key.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use crate::crypto::{self, hash, hkdf, mac16, NonceOrder, HASH_LEN, TAG_LEN};
use crate::keys::{NodePublic, PrivateKey, PublicKey};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;
pub const TYPE_COOKIE: u8 = 3;
pub const TYPE_TRANSPORT: u8 = 4;

const INITIATION_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 64;
const TRANSPORT_HEADER_LEN: usize = 16;

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// The first retries of a handshake with a peer we hold no session with.
/// A node that has just joined (or come back) is often ahead of the peer's
/// own view of the tailnet: the peer drops an initiation from a node it
/// does not know yet, and waiting [`REKEY_TIMEOUT`] to try again makes the
/// first connection take five seconds.
const FIRST_RETRIES: [Duration; 10] = {
    let mut waits = [Duration::from_secs(1); 10];
    waits[0] = Duration::from_millis(250);
    waits[1] = Duration::from_millis(500);
    waits
};
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);
/// Packets held for a peer while its handshake is in flight (default).
pub const MAX_QUEUED: usize = 128;

/// Whether `datagram` looks like WireGuard (as opposed to disco).
pub fn is_wireguard(datagram: &[u8]) -> bool {
    datagram.len() >= 4
        && (TYPE_INITIATION..=TYPE_TRANSPORT).contains(&datagram[0])
        && datagram[1..4] == [0, 0, 0]
}

/// What the tunnel wants done.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Datagrams to send, each to the given peer.
    pub send: Vec<(NodePublic, Vec<u8>)>,
    /// IP packets that arrived, each from the given peer.
    pub packets: Vec<(NodePublic, Vec<u8>)>,
}

impl Output {
    fn send(&mut self, peer: NodePublic, datagram: Vec<u8>) {
        self.send.push((peer, datagram));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WgError {
    #[error("malformed WireGuard message")]
    Malformed,
    #[error("the message failed authentication")]
    Crypto,
    #[error("the message is from an unknown peer or session")]
    Unknown,
    #[error("the message is a replay")]
    Replay,
    #[error("the session has expired")]
    Expired,
}

impl From<crypto::CryptoError> for WgError {
    fn from(_: crypto::CryptoError) -> Self {
        WgError::Crypto
    }
}

/// This node's side of every WireGuard session.
pub struct Tunnel {
    private: PrivateKey,
    public: PublicKey,
    /// `HASH(LABEL_MAC1 || our public)`: checks mac1 on messages to us.
    mac1_key: [u8; HASH_LEN],
    peers: HashMap<NodePublic, Peer>,
    /// Our local session and handshake indices, to the peer they belong to.
    indices: HashMap<u32, NodePublic>,
    max_queued: usize,
}

impl Tunnel {
    pub fn new(private: PrivateKey) -> Self {
        let public = private.public();
        Self {
            mac1_key: hash(&[LABEL_MAC1, &public.0]),
            private,
            public,
            peers: HashMap::new(),
            indices: HashMap::new(),
            max_queued: MAX_QUEUED,
        }
    }

    pub fn public(&self) -> NodePublic {
        NodePublic(self.public)
    }

    /// How many packets may wait per peer for a handshake.
    pub fn set_max_queued(&mut self, packets: usize) {
        self.max_queued = packets.max(1);
    }

    /// Allow sessions with `peer` (a no-op if already known).
    pub fn add_peer(&mut self, peer: NodePublic) {
        self.peers.entry(peer).or_insert_with(|| Peer::new(peer.0));
    }

    /// Forget `peer` and its sessions.
    pub fn remove_peer(&mut self, peer: &NodePublic) {
        if self.peers.remove(peer).is_some() {
            self.indices.retain(|_, owner| owner != peer);
        }
    }

    /// How many peers have WireGuard state.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Peers by when they were last used (sent to, heard from, or a
    /// handshake started), least recent first: the order to evict in.
    pub fn least_recently_used(&self) -> Vec<NodePublic> {
        let mut peers: Vec<(Option<Instant>, NodePublic)> = self
            .peers
            .iter()
            .map(|(k, p)| (p.last_active(), *k))
            .collect();
        peers.sort();
        peers.into_iter().map(|(_, k)| k).collect()
    }

    pub fn has_peer(&self, peer: &NodePublic) -> bool {
        self.peers.contains_key(peer)
    }

    pub fn peers(&self) -> impl Iterator<Item = &NodePublic> {
        self.peers.keys()
    }

    /// Whether `peer` has a session that can carry data right now.
    pub fn is_established(&self, peer: &NodePublic, now: Instant) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.current.as_ref())
            .is_some_and(|s| s.can_send(now))
    }

    /// Send an IP packet to `peer`: encrypted now if there is a session,
    /// else queued behind a new handshake.
    pub fn encapsulate(
        &mut self,
        peer: NodePublic,
        packet: &[u8],
        now: Instant,
    ) -> Result<Output, WgError> {
        let mut out = Output::default();
        let p = self.peers.get_mut(&peer).ok_or(WgError::Unknown)?;
        if let Some(session) = p.current.as_mut().filter(|s| s.can_send(now)) {
            let datagram = session.seal(packet);
            p.last_sent = Some(now);
            // Anything we send answers what we received.
            p.keepalive_due = None;
            let rekey = session.initiator
                && (now.duration_since(session.created) >= REKEY_AFTER_TIME
                    || session.send_counter >= REKEY_AFTER_MESSAGES);
            if packet.is_empty() {
                // A keepalive: nothing to wait for an answer to.
            } else if p.first_unanswered.is_none() {
                p.first_unanswered = Some(now);
            }
            out.send(peer, datagram);
            if rekey && p.handshake.is_none() {
                self.initiate(peer, now, &mut out);
            }
            return Ok(out);
        }
        if p.queue.len() >= self.max_queued {
            p.queue.pop_front();
        }
        p.queue.push_back(packet.to_vec());
        if p.handshake.is_none() {
            self.initiate(peer, now, &mut out);
        }
        Ok(out)
    }

    /// Handle a WireGuard datagram from anyone.
    pub fn decapsulate(&mut self, datagram: &[u8], now: Instant) -> Result<Output, WgError> {
        self.decapsulate_allowing(datagram, now, |_| false)
    }

    /// Like [`decapsulate`](Self::decapsulate), but a handshake from a peer
    /// not yet in the tunnel is accepted if `allow` says so, and the peer
    /// added then (peers are only kept for nodes actually talked to).
    pub fn decapsulate_allowing(
        &mut self,
        datagram: &[u8],
        now: Instant,
        allow: impl Fn(&NodePublic) -> bool,
    ) -> Result<Output, WgError> {
        if !is_wireguard(datagram) {
            return Err(WgError::Malformed);
        }
        match datagram[0] {
            TYPE_INITIATION => self.on_initiation(datagram, now, allow),
            TYPE_RESPONSE => self.on_response(datagram, now),
            TYPE_COOKIE => self.on_cookie(datagram, now),
            _ => self.on_transport(datagram, now),
        }
    }

    /// Run the timers: handshake retransmits, keepalives and expiry.
    pub fn tick(&mut self, now: Instant) -> Output {
        let mut out = Output::default();
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            let p = self.peers.get_mut(&key).expect("listed");
            // Expire old sessions.
            for slot in [&mut p.previous, &mut p.current, &mut p.next] {
                if slot
                    .as_ref()
                    .is_some_and(|s| now.duration_since(s.created) >= REJECT_AFTER_TIME * 3)
                {
                    let s = slot.take().expect("checked");
                    self.indices.remove(&s.local_index);
                }
            }

            // Retransmit or give up on an unanswered initiation.
            if let Some(h) = &p.handshake {
                if now.duration_since(h.started) >= REKEY_ATTEMPT_TIME {
                    let h = p.handshake.take().expect("checked");
                    self.indices.remove(&h.local_index);
                    p.queue.clear();
                    tracing::debug!("handshake with {:?} timed out", key);
                } else if now >= h.retry_at(p.current.is_none()) {
                    let (started, retries) = (h.started, h.retries + 1);
                    self.initiate(key, now, &mut out);
                    if let Some(h) = self.peers.get_mut(&key).and_then(|p| p.handshake.as_mut()) {
                        h.started = started;
                        h.retries = retries;
                    }
                }
                continue;
            }

            let Some(session) = p.current.as_ref() else {
                continue;
            };
            let usable = session.can_send(now);
            // Sent data, heard nothing back: the session may be dead.
            let unanswered = p
                .first_unanswered
                .is_some_and(|t| now.duration_since(t) >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
            // Initiator-side rekey on age, while the peer is in use.
            let stale = session.initiator
                && now.duration_since(session.created)
                    >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                && p.last_received
                    .is_some_and(|t| now.duration_since(t) < REKEY_AFTER_TIME);
            if (unanswered || stale) && usable {
                p.first_unanswered = None;
                self.initiate(key, now, &mut out);
                continue;
            }
            // Passive keepalive: we received but have not answered.
            let p = self.peers.get_mut(&key).expect("listed");
            if usable && p.keepalive_due.is_some_and(|due| now >= due) {
                let session = p.current.as_mut().expect("usable");
                let datagram = session.seal(&[]);
                p.last_sent = Some(now);
                p.keepalive_due = None;
                out.send(key, datagram);
            }
        }
        out
    }

    /// The earliest instant [`tick`](Self::tick) has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.peers
            .values()
            .filter_map(|p| {
                let handshake = p
                    .handshake
                    .as_ref()
                    .map(|h| h.retry_at(p.current.is_none()));
                let keepalive = p.keepalive_due;
                let unanswered = p
                    .first_unanswered
                    .map(|t| t + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
                [handshake, keepalive, unanswered]
                    .into_iter()
                    .flatten()
                    .min()
            })
            .min()
    }

    fn fresh_index(&mut self, peer: NodePublic) -> u32 {
        loop {
            let index = OsRng.next_u32();
            if index != 0 && !self.indices.contains_key(&index) {
                self.indices.insert(index, peer);
                return index;
            }
        }
    }

    fn initiate(&mut self, peer: NodePublic, now: Instant, out: &mut Output) {
        let local_index = self.fresh_index(peer);
        let p = self.peers.get_mut(&peer).expect("known peer");
        if let Some(old) = p.handshake.take() {
            self.indices.remove(&old.local_index);
        }
        let ephemeral = PrivateKey::generate();
        let Ok((msg, state)) = initiation(
            &self.private,
            &self.public,
            &p.remote,
            &ephemeral,
            local_index,
            p.cookie
                .as_ref()
                .filter(|c| now.duration_since(c.1) < COOKIE_LIFETIME)
                .map(|c| &c.0),
        ) else {
            self.indices.remove(&local_index);
            return;
        };
        p.last_mac1 = msg[116..132].try_into().ok();
        p.handshake = Some(Handshake {
            local_index,
            ephemeral,
            hash: state.0,
            chaining_key: state.1,
            started: now,
            sent: now,
            retries: 0,
        });
        out.send(peer, msg);
    }

    fn on_initiation(
        &mut self,
        msg: &[u8],
        now: Instant,
        allow: impl Fn(&NodePublic) -> bool,
    ) -> Result<Output, WgError> {
        if msg.len() != INITIATION_LEN {
            return Err(WgError::Malformed);
        }
        check_mac1(&self.mac1_key, msg)?;
        let sender = u32::from_le_bytes(msg[4..8].try_into().expect("4"));
        let e_i = PublicKey(msg[8..40].try_into().expect("32"));

        let mut c = hash(&[CONSTRUCTION]);
        let mut h = hash(&[&c, IDENTIFIER]);
        h = hash(&[&h, &self.public.0]);
        [c] = hkdf::<1>(&c, &e_i.0);
        h = hash(&[&h, &e_i.0]);
        let [c2, k] = hkdf::<2>(&c, &crypto::dh(&self.private, &e_i)?);
        c = c2;
        let mut static_i = msg[40..88].to_vec();
        crypto::open(&k, 0, NonceOrder::Little, &h, &mut static_i)?;
        h = hash(&[&h, &msg[40..88]]);
        let s_i = PublicKey(static_i.try_into().map_err(|_| WgError::Malformed)?);
        let peer = NodePublic(s_i);
        if !self.peers.contains_key(&peer) {
            if !allow(&peer) {
                return Err(WgError::Unknown);
            }
            self.add_peer(peer);
        }
        let p = self.peers.get(&peer).expect("present");
        let [c3, k] = hkdf::<2>(&c, &p.static_dh(&self.private)?);
        c = c3;
        let mut timestamp = msg[88..116].to_vec();
        crypto::open(&k, 0, NonceOrder::Little, &h, &mut timestamp)?;
        h = hash(&[&h, &msg[88..116]]);
        let timestamp: [u8; 12] = timestamp.try_into().map_err(|_| WgError::Malformed)?;
        if p.last_timestamp.is_some_and(|last| timestamp <= last) {
            return Err(WgError::Replay);
        }

        // Respond.
        let local_index = self.fresh_index(peer);
        let p = self.peers.get_mut(&peer).expect("checked");
        p.last_timestamp = Some(timestamp);
        let e_r = PrivateKey::generate();
        let e_r_pub = e_r.public();
        let mut resp = Vec::with_capacity(RESPONSE_LEN);
        resp.extend_from_slice(&[TYPE_RESPONSE, 0, 0, 0]);
        resp.extend_from_slice(&local_index.to_le_bytes());
        resp.extend_from_slice(&sender.to_le_bytes());
        resp.extend_from_slice(&e_r_pub.0);
        [c] = hkdf::<1>(&c, &e_r_pub.0);
        h = hash(&[&h, &e_r_pub.0]);
        [c] = hkdf::<1>(&c, &crypto::dh(&e_r, &e_i)?);
        [c] = hkdf::<1>(&c, &crypto::dh(&e_r, &s_i)?);
        let [c4, t, k] = hkdf::<3>(&c, &[0u8; 32]);
        c = c4;
        h = hash(&[&h, &t]);
        let mut empty = Vec::new();
        crypto::seal(&k, 0, NonceOrder::Little, &h, &mut empty);
        resp.extend_from_slice(&empty);
        add_macs(
            &mut resp,
            &p.remote,
            p.cookie
                .as_ref()
                .filter(|c| now.duration_since(c.1) < COOKIE_LIFETIME)
                .map(|c| &c.0),
        );

        let [recv_key, send_key] = hkdf::<2>(&c, &[]);
        let session = Session::new(local_index, sender, send_key, recv_key, false, now);
        // Usable for sending only once the initiator has used it.
        if let Some(old) = p.next.replace(session) {
            self.indices.remove(&old.local_index);
        }
        let mut out = Output::default();
        out.send(peer, resp);
        Ok(out)
    }

    fn on_response(&mut self, msg: &[u8], now: Instant) -> Result<Output, WgError> {
        if msg.len() != RESPONSE_LEN {
            return Err(WgError::Malformed);
        }
        check_mac1(&self.mac1_key, msg)?;
        let sender = u32::from_le_bytes(msg[4..8].try_into().expect("4"));
        let receiver = u32::from_le_bytes(msg[8..12].try_into().expect("4"));
        let peer = *self.indices.get(&receiver).ok_or(WgError::Unknown)?;
        let p = self.peers.get_mut(&peer).ok_or(WgError::Unknown)?;
        let h_state = p
            .handshake
            .as_ref()
            .filter(|h| h.local_index == receiver)
            .ok_or(WgError::Unknown)?;

        let e_r = PublicKey(msg[12..44].try_into().expect("32"));
        let [mut c] = hkdf::<1>(&h_state.chaining_key, &e_r.0);
        let mut h = hash(&[&h_state.hash, &e_r.0]);
        [c] = hkdf::<1>(&c, &crypto::dh(&h_state.ephemeral, &e_r)?);
        [c] = hkdf::<1>(&c, &crypto::dh(&self.private, &e_r)?);
        let [c2, t, k] = hkdf::<3>(&c, &[0u8; 32]);
        c = c2;
        h = hash(&[&h, &t]);
        let mut empty = msg[44..60].to_vec();
        crypto::open(&k, 0, NonceOrder::Little, &h, &mut empty)?;

        let [send_key, recv_key] = hkdf::<2>(&c, &[]);
        let handshake = p.handshake.take().expect("checked");
        let session = Session::new(handshake.local_index, sender, send_key, recv_key, true, now);
        if let Some(old) = p.previous.replace(session) {
            self.indices.remove(&old.local_index);
        }
        std::mem::swap(&mut p.previous, &mut p.current);
        p.first_unanswered = None;

        // Flush what waited for the handshake, or confirm with a keepalive.
        let mut out = Output::default();
        let session = p.current.as_mut().expect("just set");
        if p.queue.is_empty() {
            out.send(peer, session.seal(&[]));
        }
        while let Some(packet) = p.queue.pop_front() {
            out.send(peer, session.seal(&packet));
        }
        p.last_sent = Some(now);
        Ok(out)
    }

    fn on_cookie(&mut self, msg: &[u8], now: Instant) -> Result<Output, WgError> {
        if msg.len() != COOKIE_LEN {
            return Err(WgError::Malformed);
        }
        let receiver = u32::from_le_bytes(msg[4..8].try_into().expect("4"));
        let peer = *self.indices.get(&receiver).ok_or(WgError::Unknown)?;
        let p = self.peers.get_mut(&peer).ok_or(WgError::Unknown)?;
        let mac1 = p.last_mac1.ok_or(WgError::Unknown)?;
        let key = hash(&[LABEL_COOKIE, &p.remote.0]);
        let nonce: [u8; 24] = msg[8..32].try_into().expect("24");
        let mut cookie = msg[32..64].to_vec();
        crypto::xopen(&key, &nonce, &mac1, &mut cookie)?;
        p.cookie = Some((cookie.try_into().map_err(|_| WgError::Malformed)?, now));
        Ok(Output::default())
    }

    fn on_transport(&mut self, msg: &[u8], now: Instant) -> Result<Output, WgError> {
        if msg.len() < TRANSPORT_HEADER_LEN + TAG_LEN {
            return Err(WgError::Malformed);
        }
        let receiver = u32::from_le_bytes(msg[4..8].try_into().expect("4"));
        let counter = u64::from_le_bytes(msg[8..16].try_into().expect("8"));
        let peer = *self.indices.get(&receiver).ok_or(WgError::Unknown)?;
        let p = self.peers.get_mut(&peer).ok_or(WgError::Unknown)?;

        let slot = [&mut p.current, &mut p.next, &mut p.previous]
            .into_iter()
            .position(|s| s.as_ref().is_some_and(|s| s.local_index == receiver))
            .ok_or(WgError::Unknown)?;
        let session = match slot {
            0 => p.current.as_mut(),
            1 => p.next.as_mut(),
            _ => p.previous.as_mut(),
        }
        .expect("found");
        if now.duration_since(session.created) >= REJECT_AFTER_TIME {
            return Err(WgError::Expired);
        }
        if !session.replay.can_accept(counter) {
            return Err(WgError::Replay);
        }
        let mut packet = msg[TRANSPORT_HEADER_LEN..].to_vec();
        crypto::open(
            &session.recv_key,
            counter,
            NonceOrder::Little,
            &[],
            &mut packet,
        )?;
        if !session.replay.accept(counter) {
            return Err(WgError::Replay);
        }

        let mut out = Output::default();
        if slot == 1 {
            // The initiator used our response: the new session is live.
            let next = p.next.take().expect("found");
            if let Some(old) = p.previous.take() {
                self.indices.remove(&old.local_index);
            }
            p.previous = p.current.replace(next);
            p.handshake
                .take()
                .map(|h| self.indices.remove(&h.local_index));
            let session = p.current.as_mut().expect("just set");
            while let Some(queued) = p.queue.pop_front() {
                out.send(peer, session.seal(&queued));
                p.last_sent = Some(now);
            }
        }
        p.last_received = Some(now);
        p.first_unanswered = None;
        if !packet.is_empty() {
            p.keepalive_due.get_or_insert(now + KEEPALIVE_TIMEOUT);
            out.packets.push((peer, strip_padding(packet)));
        }
        Ok(out)
    }
}

/// Trim WireGuard's zero padding using the IP header's own length.
fn strip_padding(mut packet: Vec<u8>) -> Vec<u8> {
    let len = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => u16::from_be_bytes([packet[2], packet[3]]) as usize,
        Some(6) if packet.len() >= 40 => 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize,
        _ => packet.len(),
    };
    packet.truncate(len.min(packet.len()));
    packet
}

struct Peer {
    remote: PublicKey,
    handshake: Option<Handshake>,
    /// Sessions: the one we send on, the one before it (still receiving),
    /// and a responder session not yet confirmed by the initiator.
    current: Option<Session>,
    previous: Option<Session>,
    next: Option<Session>,
    queue: VecDeque<Vec<u8>>,
    last_timestamp: Option<[u8; 12]>,
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    /// When a passive keepalive is due, if we received data but sent none.
    keepalive_due: Option<Instant>,
    /// When we first sent data that has not been answered yet.
    first_unanswered: Option<Instant>,
    /// A cookie from the peer, and when we got it.
    cookie: Option<([u8; 16], Instant)>,
    /// mac1 of our last initiation, which a cookie reply refers to.
    last_mac1: Option<[u8; 16]>,
}

impl Peer {
    fn last_active(&self) -> Option<Instant> {
        [
            self.last_sent,
            self.last_received,
            self.handshake.as_ref().map(|h| h.started),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    fn new(remote: PublicKey) -> Self {
        Self {
            remote,
            handshake: None,
            current: None,
            previous: None,
            next: None,
            queue: VecDeque::new(),
            last_timestamp: None,
            last_sent: None,
            last_received: None,
            keepalive_due: None,
            first_unanswered: None,
            cookie: None,
            last_mac1: None,
        }
    }

    fn static_dh(&self, private: &PrivateKey) -> Result<[u8; 32], WgError> {
        Ok(crypto::dh(private, &self.remote)?)
    }
}

struct Handshake {
    local_index: u32,
    ephemeral: PrivateKey,
    hash: [u8; HASH_LEN],
    chaining_key: [u8; HASH_LEN],
    /// When this round of attempts began, and when the last one was sent.
    started: Instant,
    sent: Instant,
    /// How often it was sent again.
    retries: usize,
}

impl Handshake {
    /// When to send it again, unanswered. `first`: there is no session with
    /// the peer yet.
    fn retry_at(&self, first: bool) -> Instant {
        let wait = FIRST_RETRIES
            .get(self.retries)
            .filter(|_| first)
            .copied()
            .unwrap_or(REKEY_TIMEOUT);
        self.sent + wait
    }
}

struct Session {
    local_index: u32,
    remote_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    replay: ReplayWindow,
    initiator: bool,
    created: Instant,
}

impl Session {
    fn new(
        local_index: u32,
        remote_index: u32,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        initiator: bool,
        created: Instant,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            send_key,
            recv_key,
            send_counter: 0,
            replay: ReplayWindow::default(),
            initiator,
            created,
        }
    }

    fn can_send(&self, now: Instant) -> bool {
        now.duration_since(self.created) < REJECT_AFTER_TIME
            && self.send_counter < REJECT_AFTER_MESSAGES
    }

    fn seal(&mut self, packet: &[u8]) -> Vec<u8> {
        let counter = self.send_counter;
        self.send_counter += 1;
        let padded = packet.len().div_ceil(16) * 16;
        let mut body = Vec::with_capacity(TRANSPORT_HEADER_LEN + padded + TAG_LEN);
        body.extend_from_slice(packet);
        body.resize(padded, 0);
        crypto::seal(&self.send_key, counter, NonceOrder::Little, &[], &mut body);
        let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + body.len());
        msg.extend_from_slice(&[TYPE_TRANSPORT, 0, 0, 0]);
        msg.extend_from_slice(&self.remote_index.to_le_bytes());
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(&body);
        msg
    }
}

/// The RFC 6479 sliding window WireGuard uses against replays.
struct ReplayWindow {
    /// The highest counter accepted so far, plus one (0 = none yet).
    next: u64,
    bitmap: [u64; Self::WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            next: 0,
            bitmap: [0; Self::WORDS],
        }
    }
}

impl ReplayWindow {
    const WORDS: usize = 32;
    const SIZE: u64 = (Self::WORDS as u64 - 1) * 64;

    fn can_accept(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter >= self.next {
            return true;
        }
        if self.next - counter > Self::SIZE {
            return false;
        }
        let bit = counter % (Self::WORDS as u64 * 64);
        self.bitmap[(bit / 64) as usize] & (1 << (bit % 64)) == 0
    }

    fn accept(&mut self, counter: u64) -> bool {
        if !self.can_accept(counter) {
            return false;
        }
        let total = Self::WORDS as u64 * 64;
        if counter >= self.next {
            let current_word = self.next / 64;
            let new_word = counter / 64;
            let clear = (new_word - current_word).min(Self::WORDS as u64);
            for i in 1..=clear {
                self.bitmap[((current_word + i) % Self::WORDS as u64) as usize] = 0;
            }
            self.next = counter + 1;
        }
        let bit = counter % total;
        self.bitmap[(bit / 64) as usize] |= 1 << (bit % 64);
        true
    }
}

/// A handshake's running `(hash, chaining key)`.
type HandshakeHash = ([u8; HASH_LEN], [u8; HASH_LEN]);

/// Build a handshake initiation; returns it and `(hash, chaining key)`.
fn initiation(
    private: &PrivateKey,
    public: &PublicKey,
    remote: &PublicKey,
    ephemeral: &PrivateKey,
    local_index: u32,
    cookie: Option<&[u8; 16]>,
) -> Result<(Vec<u8>, HandshakeHash), WgError> {
    let mut c = hash(&[CONSTRUCTION]);
    let mut h = hash(&[&c, IDENTIFIER]);
    h = hash(&[&h, &remote.0]);
    let e_pub = ephemeral.public();
    [c] = hkdf::<1>(&c, &e_pub.0);
    h = hash(&[&h, &e_pub.0]);

    let mut msg = Vec::with_capacity(INITIATION_LEN);
    msg.extend_from_slice(&[TYPE_INITIATION, 0, 0, 0]);
    msg.extend_from_slice(&local_index.to_le_bytes());
    msg.extend_from_slice(&e_pub.0);

    let [c2, k] = hkdf::<2>(&c, &crypto::dh(ephemeral, remote)?);
    c = c2;
    let mut static_ = public.0.to_vec();
    crypto::seal(&k, 0, NonceOrder::Little, &h, &mut static_);
    h = hash(&[&h, &static_]);
    msg.extend_from_slice(&static_);

    let [c3, k] = hkdf::<2>(&c, &crypto::dh(private, remote)?);
    c = c3;
    let mut timestamp = tai64n().to_vec();
    crypto::seal(&k, 0, NonceOrder::Little, &h, &mut timestamp);
    h = hash(&[&h, &timestamp]);
    msg.extend_from_slice(&timestamp);

    add_macs(&mut msg, remote, cookie);
    Ok((msg, (h, c)))
}

/// Append mac1 (keyed by the receiver's public key) and mac2 (by its cookie).
fn add_macs(msg: &mut Vec<u8>, receiver: &PublicKey, cookie: Option<&[u8; 16]>) {
    let mac1 = mac16(&hash(&[LABEL_MAC1, &receiver.0]), msg);
    msg.extend_from_slice(&mac1);
    match cookie {
        Some(cookie) => {
            let mac2 = mac16(cookie, msg);
            msg.extend_from_slice(&mac2);
        }
        None => msg.extend_from_slice(&[0u8; 16]),
    }
}

fn check_mac1(mac1_key: &[u8; HASH_LEN], msg: &[u8]) -> Result<(), WgError> {
    let at = msg.len() - 32;
    if mac16(mac1_key, &msg[..at]) != msg[at..at + 16] {
        return Err(WgError::Crypto);
    }
    Ok(())
}

/// The current time as TAI64N: 8 bytes of seconds + 2^62, 4 of nanoseconds.
fn tai64n() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(0x4000_0000_0000_000a_u64 + now.as_secs()).to_be_bytes());
    // Whitened to 2^24 ns granularity, as wireguard-go does, so the
    // timestamp does not leak precise clock values.
    let nanos = now.subsec_nanos() & !0xff_ffff;
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Tunnel, Tunnel, NodePublic, NodePublic) {
        let a = Tunnel::new(PrivateKey::generate());
        let b = Tunnel::new(PrivateKey::generate());
        let (ka, kb) = (a.public(), b.public());
        let (mut a, mut b) = (a, b);
        a.add_peer(kb);
        b.add_peer(ka);
        (a, b, ka, kb)
    }

    /// Deliver every datagram in `out` to `to`, returning what it produced.
    fn deliver(out: Output, to: &mut Tunnel, now: Instant) -> Output {
        let mut all = Output::default();
        for (_, datagram) in out.send {
            let o = to.decapsulate(&datagram, now).unwrap();
            all.send.extend(o.send);
            all.packets.extend(o.packets);
        }
        all
    }

    fn ipv4(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        p.extend_from_slice(payload);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    #[test]
    fn handshake_then_data_both_ways() {
        let (mut a, mut b, ka, kb) = pair();
        let now = Instant::now();
        let packet = ipv4(b"hello");

        // a has no session: the packet waits behind an initiation.
        let out = a.encapsulate(kb, &packet, now).unwrap();
        assert_eq!(out.send.len(), 1);
        assert_eq!(out.send[0].1[0], TYPE_INITIATION);
        assert_eq!(out.send[0].1.len(), INITIATION_LEN);

        let response = deliver(out, &mut b, now);
        assert_eq!(response.send[0].1[0], TYPE_RESPONSE);
        assert!(!b.is_established(&ka, now), "b sends only once a confirms");

        // a gets the response and flushes the queued packet.
        let data = deliver(response, &mut a, now);
        assert!(a.is_established(&kb, now));
        assert_eq!(data.send[0].1[0], TYPE_TRANSPORT);
        let arrived = deliver(data, &mut b, now);
        assert_eq!(arrived.packets, vec![(ka, packet.clone())]);
        assert!(b.is_established(&ka, now));

        // And back.
        let reply = ipv4(b"world");
        let out = b.encapsulate(ka, &reply, now).unwrap();
        let arrived = deliver(out, &mut a, now);
        assert_eq!(arrived.packets, vec![(kb, reply)]);
    }

    #[test]
    fn allowed_strangers_get_a_peer_on_their_first_handshake() {
        let mut a = Tunnel::new(PrivateKey::generate());
        let mut b = Tunnel::new(PrivateKey::generate());
        let (ka, kb) = (a.public(), b.public());
        a.add_peer(kb);
        let now = Instant::now();
        let init = a.encapsulate(kb, &ipv4(b"x"), now).unwrap();
        assert!(!b.has_peer(&ka));
        assert_eq!(b.decapsulate(&init.send[0].1, now), Err(WgError::Unknown));
        let resp = b
            .decapsulate_allowing(&init.send[0].1, now, |k| *k == ka)
            .unwrap();
        assert!(b.has_peer(&ka));
        assert_eq!(resp.send[0].1[0], TYPE_RESPONSE);
    }

    #[test]
    fn replays_and_tampering_are_rejected() {
        let (mut a, mut b, _ka, kb) = pair();
        let now = Instant::now();
        let out = a.encapsulate(kb, &ipv4(b"x"), now).unwrap();
        let resp = deliver(out, &mut b, now);
        let data = deliver(resp, &mut a, now);
        let datagram = data.send[0].1.clone();
        b.decapsulate(&datagram, now).unwrap();
        assert_eq!(b.decapsulate(&datagram, now), Err(WgError::Replay));

        let mut tampered = a.encapsulate(kb, &ipv4(b"y"), now).unwrap().send[0]
            .1
            .clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(b.decapsulate(&tampered, now), Err(WgError::Crypto));
    }

    #[test]
    fn unknown_peers_are_refused() {
        let (mut a, _b, _ka, kb) = pair();
        let mut stranger = Tunnel::new(PrivateKey::generate());
        let now = Instant::now();
        let out = a.encapsulate(kb, &ipv4(b"x"), now).unwrap();
        // The initiation is for b, so its mac1 does not check out for a stranger.
        assert_eq!(
            stranger.decapsulate(&out.send[0].1, now),
            Err(WgError::Crypto)
        );
        stranger.add_peer(a.public());
    }

    #[test]
    fn unanswered_initiations_are_retried_then_dropped() {
        let (mut a, _b, _ka, kb) = pair();
        let t0 = Instant::now();
        a.encapsulate(kb, &ipv4(b"x"), t0).unwrap();
        // No session yet: soon at first, then every REKEY_TIMEOUT.
        let mut t = t0;
        for wait in FIRST_RETRIES.into_iter().chain([REKEY_TIMEOUT; 2]) {
            assert!(a.tick(t + wait - Duration::from_millis(1)).send.is_empty());
            assert_eq!(a.next_deadline(), Some(t + wait));
            t += wait;
            let retry = a.tick(t);
            assert_eq!(retry.send.len(), 1);
            assert_eq!(retry.send[0].1[0], TYPE_INITIATION);
        }
        let _ = a.tick(t0 + REKEY_ATTEMPT_TIME + Duration::from_secs(1));
        assert!(a
            .tick(t0 + REKEY_ATTEMPT_TIME + Duration::from_secs(10))
            .send
            .is_empty());
    }

    #[test]
    fn passive_keepalive_after_receiving() {
        let (mut a, mut b, ka, kb) = pair();
        let t0 = Instant::now();
        let out = a.encapsulate(kb, &ipv4(b"x"), t0).unwrap();
        let resp = deliver(out, &mut b, t0);
        let data = deliver(resp, &mut a, t0);
        deliver(data, &mut b, t0);
        // b received data and has not answered: a keepalive is due.
        assert!(b.tick(t0 + Duration::from_secs(1)).send.is_empty());
        let keepalive = b.tick(t0 + KEEPALIVE_TIMEOUT);
        assert_eq!(keepalive.send.len(), 1);
        let got = deliver(keepalive, &mut a, t0 + KEEPALIVE_TIMEOUT);
        assert!(got.packets.is_empty(), "keepalives carry no packet");
        let _ = ka;
    }

    #[test]
    fn least_recently_used_comes_first() {
        let mut t = Tunnel::new(PrivateKey::generate());
        let keys: Vec<NodePublic> = (0..3)
            .map(|_| NodePublic(PrivateKey::generate().public()))
            .collect();
        for k in &keys {
            t.add_peer(*k);
        }
        let t0 = Instant::now();
        // Used in the order 2, 0; 1 never.
        t.encapsulate(keys[2], &ipv4(b"a"), t0).unwrap();
        t.encapsulate(keys[0], &ipv4(b"b"), t0 + Duration::from_secs(1))
            .unwrap();
        assert_eq!(t.least_recently_used(), vec![keys[1], keys[2], keys[0]]);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.accept(5000));
        assert!(!w.accept(10), "too old");
        assert!(w.accept(4999));
    }

    #[test]
    fn padding_is_stripped() {
        let p = ipv4(b"abc");
        let mut padded = p.clone();
        padded.resize(32, 0);
        assert_eq!(strip_padding(padded), p);
    }
}
