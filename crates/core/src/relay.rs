//! The peer relay's client, sans-IO: a path to a peer through another node
//! of the tailnet that forwards UDP for the two of us, for when no direct
//! path can be found. Faster than DERP: it is UDP end to end, and the relay
//! is where the tailnet's admin put it.
//!
//! What happens, as tailscale's `relayManager` does it:
//! 1. **Allocate.** Over DERP, each relay server we may use is asked for an
//!    endpoint for our disco key and the peer's ([`RelayClient::discover`]).
//!    Asked again after 3 s, given up after 10.
//! 2. **Tell the peer.** The endpoint goes to the peer in a call-me-maybe-via
//!    (over DERP); a peer that allocated tells us the same way
//!    ([`RelayClient::on_call_me_maybe_via`]).
//! 3. **Bind.** Both peers bind to the endpoint: a bind message to each of
//!    the server's addresses, its challenge echoed in an answer. The server
//!    takes one source address per peer.
//! 4. **Probe.** A disco ping to the peer through the relay follows the
//!    answer at once. The relay drops it until the peer has bound too, so a
//!    ping from the peer is answered with another of ours; a pong makes the
//!    path [`Ready`].
//!
//! Messages come in decoded and go out as [`Send`]s: sealing, the Geneve
//! header and the peer's own state are the caller's ([`crate::paths`]).

#[allow(unused_imports)]
use crate::prelude::*;
use crate::time::{Duration, Instant};
use core::net::SocketAddr;

use crate::disco::{Message, RelayBind, RelayEndpoint, TxId};
use crate::geneve::VNI_MAX;
use crate::keys::{DiscoPublic, NodePublic};

/// When an allocation request is sent again: DERP may lose it, and a relay
/// server that just started is not ready.
pub const ALLOCATE_RETRY: Duration = Duration::from_secs(3);
/// How long an allocation is waited for.
pub const ALLOCATE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a bind handshake and its probing may take, whatever lifetime
/// the server gives the unbound endpoint.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Pings sent per handshake: a ping from the peer triggers one of ours.
pub const MAX_PINGS: usize = 10;
/// When a handshake repeats what got no answer: its bind (a few times), then
/// its answer with a ping (while it has pings left). tailscale sends each
/// once and waits for the next discovery, 30 s later; one lost datagram
/// should not cost that.
pub const HANDSHAKE_RETRY: Duration = Duration::from_secs(2);
/// How often a bind is sent again.
pub const BIND_RETRIES: u8 = 3;
/// Allocations and handshakes under way at once, all peers together.
pub const MAX_WORK: usize = 32;
/// The first capability version whose client speaks through peer relays
/// (allocation over disco).
pub const RELAY_CAPABLE: u16 = 121;

/// A node of the tailnet we may use as a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server {
    pub node: NodePublic,
    /// Its node's disco key (allocation requests are sealed to it; the bind
    /// handshake has a key of the relay's own).
    pub disco: DiscoPublic,
    pub home_region: Option<i32>,
}

/// The peer a relay path is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remote {
    pub node: NodePublic,
    pub disco: DiscoPublic,
    pub home_region: Option<i32>,
}

/// The relay path a peer is on right now, if it is on one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Current {
    pub server: DiscoPublic,
    pub vni: u32,
    /// Whether it answered lately.
    pub trusted: bool,
}

/// A message to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Send {
    /// Over DERP `region` to `node`, sealed to `disco`.
    Derp {
        region: i32,
        node: NodePublic,
        disco: DiscoPublic,
        msg: Message,
    },
    /// To `addr` in a Geneve header with `vni` (and the control bit for the
    /// relay itself), sealed to `disco`: the relay's key when `control`, the
    /// peer's otherwise.
    Relay {
        addr: SocketAddr,
        vni: u32,
        control: bool,
        disco: DiscoPublic,
        msg: Message,
    },
}

/// A relay path that carried a ping and its pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    pub peer: NodePublic,
    /// The relay's address our bind was taken from.
    pub addr: SocketAddr,
    pub vni: u32,
    pub server: DiscoPublic,
    pub latency: Duration,
}

struct Allocation {
    remote: Remote,
    server: Server,
    generation: u32,
    started: Instant,
    /// Whether it was sent a second time.
    resent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    /// Bind sent to every address of the server.
    Asked,
    /// Its challenge answered, from the address it came from: the one the
    /// server now takes our packets from.
    Answered(SocketAddr),
}

impl Bound {
    fn at(self, addr: SocketAddr) -> bool {
        self == Bound::Answered(addr)
    }
}

struct Handshake {
    remote: Remote,
    endpoint: RelayEndpoint,
    generation: u32,
    deadline: Instant,
    state: Bound,
    /// The challenge answered, to answer it again.
    challenge: [u8; 32],
    pings: Vec<(TxId, Instant)>,
    /// When the bind, or the answer, last went out, and how often the bind
    /// went again.
    sent: Instant,
    bind_retries: u8,
}

/// See the module docs.
pub struct RelayClient {
    disco: DiscoPublic,
    node: NodePublic,
    servers: Vec<Server>,
    allocations: Vec<Allocation>,
    handshakes: Vec<Handshake>,
    allocate_generation: u32,
    handshake_generation: u32,
}

/// The two keys an endpoint is for, in the order the server compares them.
fn pair(a: DiscoPublic, b: DiscoPublic) -> [DiscoPublic; 2] {
    if a.0 <= b.0 {
        [a, b]
    } else {
        [b, a]
    }
}

impl RelayClient {
    pub fn new(disco: DiscoPublic, node: NodePublic) -> Self {
        Self {
            disco,
            node,
            servers: Vec::new(),
            allocations: Vec::new(),
            handshakes: Vec::new(),
            allocate_generation: 0,
            handshake_generation: 0,
        }
    }

    /// The relay servers we may use (from the netmap and the capability
    /// grants). Work on a server that left is dropped.
    pub fn set_servers(&mut self, servers: Vec<Server>) {
        self.allocations
            .retain(|a| servers.iter().any(|s| s.node == a.server.node));
        self.servers = servers;
    }

    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// Whether anything is under way for `peer`.
    pub fn busy_with(&self, peer: &NodePublic) -> bool {
        self.allocations.iter().any(|a| a.remote.node == *peer)
            || self.handshakes.iter().any(|h| h.remote.node == *peer)
    }

    /// Allocations and handshakes under way (for tests and diagnostics).
    pub fn work(&self) -> usize {
        self.allocations.len() + self.handshakes.len()
    }

    /// Ask every relay server for an endpoint to `remote`, unless something
    /// is under way for it already.
    pub fn discover(&mut self, remote: &Remote, now: Instant, out: &mut Vec<Send>) {
        if self.busy_with(&remote.node) {
            return;
        }
        for server in self.servers.clone() {
            // A peer is not reached through itself, and a server without a
            // DERP home cannot be asked.
            let Some(region) = server.home_region else {
                continue;
            };
            if server.node == remote.node || self.work() >= MAX_WORK {
                continue;
            }
            self.allocate_generation = self.allocate_generation.wrapping_add(1).max(1);
            let allocation = Allocation {
                remote: *remote,
                server,
                generation: self.allocate_generation,
                started: now,
                resent: false,
            };
            out.push(self.request(&allocation, region));
            self.allocations.push(allocation);
        }
    }

    fn request(&self, allocation: &Allocation, region: i32) -> Send {
        Send::Derp {
            region,
            node: allocation.server.node,
            disco: allocation.server.disco,
            msg: Message::AllocateRelay {
                clients: pair(self.disco, allocation.remote.disco),
                generation: allocation.generation,
            },
        }
    }

    /// A relay server's answer to an allocation request, over DERP from the
    /// node `from`.
    pub fn on_allocated(
        &mut self,
        from: &NodePublic,
        generation: u32,
        endpoint: RelayEndpoint,
        current: impl Fn(&NodePublic) -> Option<Current>,
        now: Instant,
        out: &mut Vec<Send>,
    ) {
        let Some(at) = self.allocations.iter().position(|a| {
            a.server.node == *from
                && a.generation == generation
                && pair(self.disco, a.remote.disco)
                    == pair(endpoint.clients[0], endpoint.clients[1])
        }) else {
            return;
        };
        let allocation = self.allocations.swap_remove(at);
        let current = current(&allocation.remote.node);
        self.endpoint(allocation.remote, endpoint, true, current, now, out);
    }

    /// The peer `remote` allocated an endpoint and told us of it (over DERP,
    /// which the caller has checked, with who sent it).
    pub fn on_call_me_maybe_via(
        &mut self,
        remote: &Remote,
        endpoint: RelayEndpoint,
        current: Option<Current>,
        now: Instant,
        out: &mut Vec<Send>,
    ) {
        self.endpoint(*remote, endpoint, false, current, now, out);
    }

    /// An endpoint to `remote` became known: bind to it, unless we know it
    /// already or are on it. `ours`: we allocated it, so the peer hears.
    fn endpoint(
        &mut self,
        remote: Remote,
        endpoint: RelayEndpoint,
        ours: bool,
        current: Option<Current>,
        now: Instant,
        out: &mut Vec<Send>,
    ) {
        // For the two of us, and somewhere to send to.
        let usable = |addr: &SocketAddr| !addr.ip().is_unspecified() && addr.port() != 0;
        if pair(endpoint.clients[0], endpoint.clients[1]) != pair(self.disco, remote.disco)
            || endpoint.vni == 0
            || endpoint.vni > VNI_MAX
            || !endpoint.addrs.iter().any(usable)
        {
            return;
        }
        // The server's disco key and the VNI name an endpoint; of two
        // descriptions of it the higher Lamport id is the later. So too for
        // a peer's endpoint on one server: one at a time, the latest.
        let same = |h: &Handshake| {
            h.endpoint.server == endpoint.server
                && (h.endpoint.vni == endpoint.vni || h.remote.node == remote.node)
        };
        if self
            .handshakes
            .iter()
            .any(|h| same(h) && h.endpoint.lamport_id >= endpoint.lamport_id)
        {
            return;
        }
        self.handshakes.retain(|h| !same(h));

        if ours {
            if let Some(region) = remote.home_region {
                out.push(Send::Derp {
                    region,
                    node: remote.node,
                    disco: remote.disco,
                    msg: Message::CallMeMaybeVia(endpoint.clone()),
                });
            }
        }
        // On this very endpoint, and it answers: a new handshake could move
        // us to another source address, and the relay takes only one.
        if current
            .is_some_and(|c| c.trusted && c.server == endpoint.server && c.vni == endpoint.vni)
        {
            return;
        }
        if self.work() >= MAX_WORK {
            return;
        }
        self.handshake_generation = self.handshake_generation.wrapping_add(1).max(1);
        let handshake = Handshake {
            remote,
            deadline: now + endpoint.bind_lifetime.min(HANDSHAKE_TIMEOUT),
            endpoint,
            generation: self.handshake_generation,
            state: Bound::Asked,
            challenge: [0; 32],
            pings: Vec::new(),
            sent: now,
            bind_retries: 0,
        };
        bind(&handshake, out);
        self.handshakes.push(handshake);
    }

    /// Whether a handshake with the relay whose disco key is `server` is
    /// under way: only then is a message under the control bit opened.
    pub fn expects(&self, server: &DiscoPublic) -> bool {
        self.handshakes.iter().any(|h| h.endpoint.server == *server)
    }

    /// A relay's challenge, from `src` under `vni` with the control bit,
    /// sealed by `server`.
    pub fn on_challenge(
        &mut self,
        server: &DiscoPublic,
        src: SocketAddr,
        vni: u32,
        challenge: &RelayBind,
        now: Instant,
        out: &mut Vec<Send>,
    ) {
        // Another handshake already speaks from this address under this VNI.
        if self
            .handshakes
            .iter()
            .any(|h| h.state.at(src) && h.endpoint.vni == vni)
        {
            return;
        }
        let node = self.node;
        let Some(h) = self.handshakes.iter_mut().find(|h| {
            h.endpoint.server == *server
                && h.endpoint.vni == vni
                // The sealed VNI is the header's, or the header was changed
                // on the way.
                && challenge.vni == vni
                && challenge.remote == h.remote.disco
                && challenge.generation == h.generation
        }) else {
            return;
        };
        // The server answers the first address it hears a bind from: one
        // challenge is answered.
        if h.state != Bound::Asked {
            return;
        }
        h.state = Bound::Answered(src);
        h.challenge = challenge.challenge;
        answer(h, node, src, now, out);
    }

    /// A ping from the peer with disco key `peer` came through a relay, from
    /// `src` under `vni` (the caller answers it). If we are probing that
    /// path, our own ping was likely dropped before the peer had bound:
    /// another.
    pub fn on_ping(
        &mut self,
        peer: &DiscoPublic,
        src: SocketAddr,
        vni: u32,
        now: Instant,
        out: &mut Vec<Send>,
    ) {
        let node = self.node;
        if let Some(h) = self
            .handshakes
            .iter_mut()
            .find(|h| h.state.at(src) && h.endpoint.vni == vni && h.remote.disco == *peer)
        {
            ping(h, node, src, now, out);
        }
    }

    /// A pong from the peer with disco key `peer` came through a relay. If
    /// it answers a handshake's ping, the path works.
    pub fn on_pong(
        &mut self,
        peer: &DiscoPublic,
        src: SocketAddr,
        vni: u32,
        tx: &TxId,
        now: Instant,
    ) -> Option<Ready> {
        let at = self
            .handshakes
            .iter()
            .position(|h| h.state.at(src) && h.endpoint.vni == vni && h.remote.disco == *peer)?;
        let sent = self.handshakes[at]
            .pings
            .iter()
            .find(|(sent, _)| sent == tx)?
            .1;
        let h = self.handshakes.swap_remove(at);
        Some(Ready {
            peer: h.remote.node,
            addr: src,
            vni,
            server: h.endpoint.server,
            latency: now.saturating_duration_since(sent),
        })
    }

    /// Requests to send again, and what took too long.
    pub fn tick(&mut self, now: Instant, out: &mut Vec<Send>) {
        self.handshakes.retain(|h| now < h.deadline);
        let node = self.node;
        for h in &mut self.handshakes {
            if now.saturating_duration_since(h.sent) < HANDSHAKE_RETRY {
                continue;
            }
            match h.state {
                Bound::Asked if h.bind_retries < BIND_RETRIES => {
                    h.bind_retries += 1;
                    h.sent = now;
                    bind(h, out);
                }
                // The answer too: lost, the relay never took us, and drops
                // the ping behind it.
                Bound::Answered(addr) if h.pings.len() < MAX_PINGS => {
                    answer(h, node, addr, now, out)
                }
                _ => {}
            }
        }
        self.allocations
            .retain(|a| now.saturating_duration_since(a.started) < ALLOCATE_TIMEOUT);
        let mut again = Vec::new();
        for a in &mut self.allocations {
            if !a.resent && now.saturating_duration_since(a.started) >= ALLOCATE_RETRY {
                a.resent = true;
                again.push((a.remote, a.server, a.generation));
            }
        }
        for (remote, server, generation) in again {
            if let Some(region) = server.home_region {
                out.push(Send::Derp {
                    region,
                    node: server.node,
                    disco: server.disco,
                    msg: Message::AllocateRelay {
                        clients: pair(self.disco, remote.disco),
                        generation,
                    },
                });
            }
        }
    }

    /// When [`tick`](Self::tick) next has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        let allocations = self.allocations.iter().map(|a| {
            if a.resent {
                a.started + ALLOCATE_TIMEOUT
            } else {
                a.started + ALLOCATE_RETRY
            }
        });
        let handshakes = self.handshakes.iter().map(|h| {
            let again = match h.state {
                Bound::Asked => h.bind_retries < BIND_RETRIES,
                Bound::Answered(_) => h.pings.len() < MAX_PINGS,
            };
            if again {
                h.deadline.min(h.sent + HANDSHAKE_RETRY)
            } else {
                h.deadline
            }
        });
        allocations.chain(handshakes).min()
    }

    /// Drop what is under way for `peer` (it left, or restarted).
    pub fn forget(&mut self, peer: &NodePublic) {
        self.allocations.retain(|a| a.remote.node != *peer);
        self.handshakes.retain(|h| h.remote.node != *peer);
    }

    /// Drop everything under way (the network changed).
    pub fn reset(&mut self) {
        self.allocations.clear();
        self.handshakes.clear();
    }
}

/// The handshake's bind, to every address of the server that can be sent to.
fn bind(h: &Handshake, out: &mut Vec<Send>) {
    let usable = |addr: &&SocketAddr| !addr.ip().is_unspecified() && addr.port() != 0;
    for addr in h.endpoint.addrs.iter().filter(usable) {
        out.push(Send::Relay {
            addr: *addr,
            vni: h.endpoint.vni,
            control: true,
            disco: h.endpoint.server,
            msg: Message::RelayBind(RelayBind {
                vni: h.endpoint.vni,
                generation: h.generation,
                remote: h.remote.disco,
                challenge: [0; 32],
            }),
        });
    }
}

/// The answer to the relay's challenge, to where it came from, and a ping
/// to the peer behind it.
fn answer(h: &mut Handshake, node: NodePublic, to: SocketAddr, now: Instant, out: &mut Vec<Send>) {
    h.sent = now;
    out.push(Send::Relay {
        addr: to,
        vni: h.endpoint.vni,
        control: true,
        disco: h.endpoint.server,
        msg: Message::RelayAnswer(RelayBind {
            vni: h.endpoint.vni,
            generation: h.generation,
            remote: h.remote.disco,
            challenge: h.challenge,
        }),
    });
    ping(h, node, to, now, out);
}

/// A ping to the peer through the relay at `to`, if the handshake has any left.
fn ping(h: &mut Handshake, node: NodePublic, to: SocketAddr, now: Instant, out: &mut Vec<Send>) {
    if h.pings.len() >= MAX_PINGS {
        return;
    }
    let mut tx = [0u8; 12];
    crate::random::fill(&mut tx);
    h.pings.push((tx, now));
    out.push(Send::Relay {
        addr: to,
        vni: h.endpoint.vni,
        control: false,
        disco: h.remote.disco,
        msg: Message::Ping {
            tx,
            node_key: Some(node),
        },
    });
}

#[cfg(test)]
mod tests;
