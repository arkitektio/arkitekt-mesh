//! A peer relay, sans-IO: this node forwarding UDP for two peers that find
//! no direct path to each other, as tailscale's `net/udprelay` does it.
//!
//! - **Allocation.** Two disco keys get an endpoint: a VNI, and a place in a
//!   table. Asked again for the same two, the same endpoint is described
//!   ([`RelayServer::allocate`]). Who may ask is the caller's to decide (the
//!   tailnet's `tailscale.com/cap/relay` grant).
//! - **Binding.** A client sends a bind under the endpoint's VNI with the
//!   control bit. The answer is a challenge: a MAC over what it sent and the
//!   address it came from, under a secret that changes every two minutes.
//!   Nothing is kept for it, so a bind from a forged address costs a reply
//!   and no state. The client's answer, the challenge echoed from the same
//!   address, binds it: from then on its packets are taken from there.
//! - **Forwarding.** Once both are bound, a datagram under the VNI from the
//!   one's address goes to the other's, as it is. The relay reads none of
//!   it: disco is sealed between the peers, WireGuard is WireGuard.
//! - **Expiry.** An endpoint not bound by both within the bind lifetime
//!   goes, and so does a bound one either side of which went quiet.
//!
//! Datagrams in, at most one datagram out ([`RelayServer::handle_datagram`]).

#[allow(unused_imports)]
use crate::prelude::*;
use crate::time::{Duration, Instant};
use core::net::SocketAddr;
use hashbrown::HashMap;

use crate::disco::{self, Message, RelayBind, RelayEndpoint};
use crate::geneve::{self, Protocol, VNI_MAX};
use crate::keys::{DiscoPublic, PrivateKey};
use crate::nacl::SharedBox;

/// How long an endpoint waits for both peers to bind.
pub const BIND_LIFETIME: Duration = Duration::from_secs(30);
/// How long a bound endpoint is kept with either side silent.
pub const STEADY_STATE_LIFETIME: Duration = Duration::from_secs(300);
/// How often the secret the challenges are made with changes. The one
/// before it still counts: a challenge is good for two to four minutes.
pub const SECRET_ROTATION: Duration = Duration::from_secs(120);
/// Endpoints at once, unless set otherwise: a pair of peers each.
pub const MAX_ENDPOINTS: usize = 4096;

/// Why no endpoint was allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The relay does not know yet where it can be reached: ask again.
    #[error("the relay has no address to give yet")]
    NotReady,
    #[error("a relay endpoint is for two peers, neither of them the relay")]
    BadPair,
    #[error("the relay has no endpoint to spare")]
    Full,
}

/// One endpoint's traffic, for whoever watches the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub vni: u32,
    pub clients: [DiscoPublic; 2],
    /// Where each client bound from, once it has.
    pub bound: [Option<SocketAddr>; 2],
    /// Datagrams and bytes forwarded for each client.
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
}

struct Endpoint {
    clients: [DiscoPublic; 2],
    boxes: [SharedBox; 2],
    lamport_id: u64,
    allocated: Instant,
    /// The handshake under way for each client (0: none).
    generation: [u32; 2],
    bound: [Option<SocketAddr>; 2],
    seen: [Instant; 2],
    packets: [u64; 2],
    bytes: [u64; 2],
}

impl Endpoint {
    fn is_bound(&self) -> bool {
        self.bound.iter().all(Option::is_some)
    }

    fn expired(&self, now: Instant) -> bool {
        if !self.is_bound() {
            return now.saturating_duration_since(self.allocated) > BIND_LIFETIME;
        }
        self.seen
            .iter()
            .any(|seen| now.saturating_duration_since(*seen) > STEADY_STATE_LIFETIME)
    }
}

/// See the module docs.
pub struct RelayServer {
    disco: PrivateKey,
    public: DiscoPublic,
    /// The newest first; the one before it still verifies.
    secrets: [[u8; 32]; 2],
    rotated: Option<Instant>,
    /// Where clients are told to reach us.
    addrs: Vec<SocketAddr>,
    endpoints: HashMap<u32, Endpoint>,
    by_pair: HashMap<[DiscoPublic; 2], u32>,
    lamport: u64,
    next_vni: u32,
    max_endpoints: usize,
}

fn pair(a: DiscoPublic, b: DiscoPublic) -> [DiscoPublic; 2] {
    if a.0 <= b.0 {
        [a, b]
    } else {
        [b, a]
    }
}

impl Default for RelayServer {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayServer {
    /// A relay with a disco key of its own, made now and kept for its life:
    /// with the Lamport id it names an allocation.
    pub fn new() -> Self {
        let disco = PrivateKey::generate();
        Self {
            public: DiscoPublic(disco.public()),
            disco,
            secrets: [[0; 32]; 2],
            rotated: None,
            addrs: Vec::new(),
            endpoints: HashMap::new(),
            by_pair: HashMap::new(),
            lamport: 0,
            next_vni: 1,
            max_endpoints: MAX_ENDPOINTS,
        }
    }

    /// The key clients seal the bind handshake to.
    pub fn disco(&self) -> DiscoPublic {
        self.public
    }

    pub fn set_max_endpoints(&mut self, max: usize) {
        self.max_endpoints = max.max(1);
    }

    /// Where clients may reach the relay's socket: what an allocation tells
    /// them. Without any, nothing is allocated.
    pub fn set_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.addrs = addrs;
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// An endpoint for the peers with disco keys `a` and `b`: the one they
    /// have, or a new one.
    pub fn allocate(
        &mut self,
        a: DiscoPublic,
        b: DiscoPublic,
        now: Instant,
    ) -> Result<RelayEndpoint, Refused> {
        if self.addrs.is_empty() {
            return Err(Refused::NotReady);
        }
        if a == b || a == self.public || b == self.public {
            return Err(Refused::BadPair);
        }
        self.expire(now);
        let clients = pair(a, b);
        let vni = match self.by_pair.get(&clients) {
            Some(vni) => *vni,
            None => {
                if self.endpoints.len() >= self.max_endpoints {
                    return Err(Refused::Full);
                }
                let vni = self.free_vni().ok_or(Refused::Full)?;
                self.lamport += 1;
                self.endpoints.insert(
                    vni,
                    Endpoint {
                        clients,
                        boxes: [
                            SharedBox::new(&self.disco, &clients[0].0),
                            SharedBox::new(&self.disco, &clients[1].0),
                        ],
                        lamport_id: self.lamport,
                        allocated: now,
                        generation: [0; 2],
                        bound: [None; 2],
                        seen: [now; 2],
                        packets: [0; 2],
                        bytes: [0; 2],
                    },
                );
                self.by_pair.insert(clients, vni);
                tracing::debug!(
                    "relay: allocated vni {vni} for {:?} and {:?}",
                    clients[0],
                    clients[1]
                );
                vni
            }
        };
        let endpoint = &self.endpoints[&vni];
        Ok(RelayEndpoint {
            server: self.public,
            clients,
            lamport_id: endpoint.lamport_id,
            vni,
            bind_lifetime: BIND_LIFETIME,
            steady_state_lifetime: STEADY_STATE_LIFETIME,
            addrs: self.addrs.clone(),
        })
    }

    /// The next VNI not in use, counting around.
    fn free_vni(&mut self) -> Option<u32> {
        for _ in 0..VNI_MAX {
            let vni = self.next_vni;
            self.next_vni = if vni >= VNI_MAX { 1 } else { vni + 1 };
            if !self.endpoints.contains_key(&vni) {
                return Some(vni);
            }
        }
        None
    }

    /// A datagram on the relay's socket, from `src`. Returns what to send:
    /// a challenge back to `src`, or the datagram itself to the other peer.
    pub fn handle_datagram(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let src = SocketAddr::new(src.ip().to_canonical(), src.port());
        // Any header of ours; what a data packet carries is not looked at.
        let (header, payload) = geneve::unwrap(datagram)?;
        if !header.control {
            let endpoint = self.endpoints.get_mut(&header.vni)?;
            if !endpoint.is_bound() {
                return None;
            }
            let from = endpoint.bound.iter().position(|b| *b == Some(src))?;
            endpoint.seen[from] = now;
            endpoint.packets[from] += 1;
            endpoint.bytes[from] += datagram.len() as u64;
            return Some((endpoint.bound[1 - from]?, datagram.to_vec()));
        }
        if header.protocol != Protocol::Disco {
            return None;
        }
        let secrets = self.secrets(now);
        let public = self.public;
        let endpoint = self.endpoints.get_mut(&header.vni)?;
        let sender = disco::sender(payload)?;
        let index = endpoint.clients.iter().position(|c| *c == sender)?;
        let other = endpoint.clients[1 - index];
        // The sealed VNI is the header's and the peer the other of the two,
        // or it is not this endpoint's handshake.
        let ours = |bind: &RelayBind| bind.vni == header.vni && bind.remote == other;
        match disco::opened(&endpoint.boxes[index], payload)? {
            Message::RelayBind(bind) if ours(&bind) && bind.generation != 0 => {
                endpoint.generation[index] = bind.generation;
                let challenge = Message::RelayChallenge(RelayBind {
                    challenge: mac(&secrets[0], src, &bind),
                    ..bind
                });
                let sealed = disco::sealed(&public, &endpoint.boxes[index], &challenge);
                Some((src, header.wrap(&sealed)))
            }
            Message::RelayAnswer(answer)
                if ours(&answer)
                    && answer.generation != 0
                    && answer.generation == endpoint.generation[index] =>
            {
                let good = secrets
                    .iter()
                    .any(|secret| same(&mac(secret, src, &answer), &answer.challenge));
                if good {
                    if endpoint.bound[index] != Some(src) {
                        tracing::debug!("relay: vni {} bound for {sender:?} at {src}", header.vni);
                    }
                    endpoint.bound[index] = Some(src);
                    endpoint.seen[index] = now;
                    endpoint.generation[index] = 0;
                }
                None
            }
            _ => None,
        }
    }

    /// The secrets challenges are made and checked with, rotated when due.
    /// A relay nobody spoke to for two rotations has let both go: the one
    /// before the newest is never older than two rotations.
    fn secrets(&mut self, now: Instant) -> [[u8; 32]; 2] {
        let since = self.rotated.map(|at| now.saturating_duration_since(at));
        if since.is_none_or(|since| since >= SECRET_ROTATION) {
            self.secrets[1] = self.secrets[0];
            crate::random::fill(&mut self.secrets[0]);
            if since.is_none_or(|since| since >= SECRET_ROTATION * 2) {
                // No secret before the first, and none that old: nothing
                // verifies against zeros or a secret long retired.
                self.secrets[1] = self.secrets[0];
            }
            self.rotated = Some(now);
        }
        self.secrets
    }

    /// Drop the endpoints whose time is up.
    pub fn expire(&mut self, now: Instant) {
        let by_pair = &mut self.by_pair;
        self.endpoints.retain(|vni, endpoint| {
            let keep = !endpoint.expired(now);
            if !keep {
                tracing::debug!("relay: vni {vni} expired");
                by_pair.remove(&endpoint.clients);
            }
            keep
        });
    }

    /// The endpoints, for whoever watches.
    pub fn sessions(&self) -> Vec<Session> {
        let mut sessions: Vec<Session> = self
            .endpoints
            .iter()
            .map(|(vni, e)| Session {
                vni: *vni,
                clients: e.clients,
                bound: e.bound,
                packets: e.packets,
                bytes: e.bytes,
            })
            .collect();
        sessions.sort_by_key(|s| s.vni);
        sessions
    }
}

/// The challenge for a bind `from` an address: only who receives there can
/// echo it, and it is good for this endpoint, this peer and this handshake.
fn mac(secret: &[u8; 32], from: SocketAddr, bind: &RelayBind) -> [u8; 32] {
    let (ip, port) = match from.ip() {
        core::net::IpAddr::V4(v4) => (v4.to_ipv6_mapped().octets(), from.port()),
        core::net::IpAddr::V6(v6) => (v6.octets(), from.port()),
    };
    crate::crypto::hmac(
        secret,
        &[
            &bind.vni.to_be_bytes(),
            &bind.generation.to_be_bytes(),
            &bind.remote.0 .0,
            &ip,
            &port.to_be_bytes(),
        ],
    )
}

/// Equal, compared in time that does not tell where they differ.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests;
