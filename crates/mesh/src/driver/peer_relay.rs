//! This node as a peer relay: a UDP port of its own on which it forwards
//! for pairs of peers that find no direct path to each other
//! (docs/rfc10-peer-relays.md). The forwarding is
//! [`mesh_core::relay_server`]'s; here are its sockets, where it says it can
//! be reached, and the endpoints it hands the peers that ask.
//!
//! The port has to be reachable by both peers of a pair: opened in the
//! firewall, forwarded by the router. Where the relay is, it works out as
//! far as it can (its address on the default route, and what a STUN server
//! sees of the port); behind a forward to another port or address, say so
//! (`endpoints`).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mesh_core::relay_server::{RelayServer, Session};
use mesh_core::time as clock;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::node::{Node, Shared};
use crate::stun;

/// How often endpoints whose time is up are dropped.
const EXPIRE_EVERY: Duration = Duration::from_secs(10);
/// How often the relay asks STUN where its port is seen from.
const DISCOVER_EVERY: Duration = Duration::from_secs(300);
/// STUN servers asked each time.
const STUN_SERVERS: usize = 3;

pub(super) type SharedRelay = Arc<Mutex<RelayServer>>;

/// A running peer relay; stopped when dropped.
pub struct PeerRelay {
    shared: Arc<Shared>,
    server: SharedRelay,
    tasks: Vec<JoinHandle<()>>,
    port: u16,
}

impl PeerRelay {
    /// The UDP port it forwards on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Where it tells peers to reach it, as known right now.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        lock(&self.server).addrs().to_vec()
    }

    /// The pairs it has endpoints for, and what it forwarded for them.
    pub fn sessions(&self) -> Vec<Session> {
        lock(&self.server).sessions()
    }
}

impl Drop for PeerRelay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.shared.set_relay(None);
    }
}

fn lock(server: &SharedRelay) -> std::sync::MutexGuard<'_, RelayServer> {
    server.lock().unwrap_or_else(|e| e.into_inner())
}

struct Sockets {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

impl Sockets {
    async fn send(&self, to: SocketAddr, data: &[u8]) {
        let to = SocketAddr::new(to.ip().to_canonical(), to.port());
        let socket = match (to.is_ipv6(), &self.v6) {
            (true, Some(v6)) => v6,
            (true, None) => return,
            (false, _) => &self.v4,
        };
        let _ = socket.send_to(data, to).await;
    }
}

/// Where the relay can be reached, as far as it knows: what it was told,
/// its address on the default route, and what STUN saw.
#[derive(Default)]
struct Reach {
    told: Vec<SocketAddr>,
    seen: [Option<SocketAddr>; 2],
    /// The STUN requests in flight.
    asked: Vec<stun::TxId>,
}

impl Reach {
    fn addrs(&self, port: u16, v6: bool) -> Vec<SocketAddr> {
        let mut addrs = self.told.clone();
        // With addresses told, only those: the relay is behind a forward
        // its own view of the network says nothing true about.
        if addrs.is_empty() {
            addrs.extend(super::node::local_endpoint(port));
            if v6 {
                addrs.extend(super::node::local_endpoint6(port));
            }
            addrs.extend(self.seen.iter().flatten());
        }
        addrs.sort();
        addrs.dedup();
        addrs
    }
}

impl Node {
    /// Relay UDP on `port` for the peers the tailnet lets ask
    /// (`tailscale.com/cap/relay` towards this node). `endpoints` are the
    /// addresses peers are told to reach the port at, for a relay behind a
    /// port forward; empty, it tells its address on the default route and
    /// what a STUN server sees.
    pub async fn serve_peer_relay(
        &self,
        port: u16,
        endpoints: Vec<SocketAddr>,
    ) -> io::Result<PeerRelay> {
        let named =
            |e: io::Error| io::Error::new(e.kind(), format!("the relay's UDP port {port}: {e}"));
        let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
            .await
            .map_err(named)?;
        let port = v4.local_addr()?.port();
        let v6 = bind_v6(port);
        let sockets = Arc::new(Sockets { v4, v6 });
        let has_v6 = sockets.v6.is_some();

        let server: SharedRelay = Arc::new(Mutex::new(RelayServer::new()));
        let reach = Arc::new(Mutex::new(Reach {
            told: endpoints,
            ..Reach::default()
        }));
        let publish = {
            let (server, reach) = (server.clone(), reach.clone());
            move || {
                let addrs = reach
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .addrs(port, has_v6);
                let mut server = lock(&server);
                if server.addrs() != addrs {
                    tracing::info!("the peer relay is reached at {addrs:?}");
                    server.set_addrs(addrs);
                }
            }
        };
        publish();

        let mut tasks = Vec::new();
        for is_v6 in [false, true].into_iter().filter(|v6| !v6 || has_v6) {
            let (sockets, server, reach, publish) = (
                sockets.clone(),
                server.clone(),
                reach.clone(),
                publish.clone(),
            );
            tasks.push(tokio::spawn(async move {
                let socket = match (&sockets.v6, is_v6) {
                    (Some(v6), true) => v6,
                    _ => &sockets.v4,
                };
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                        continue;
                    };
                    let data = &buf[..n];
                    if stun::is_stun(data) {
                        // Where a STUN server we asked sees this port.
                        if let Some((tx, addr)) = stun::parse_response(data) {
                            let mut reach = reach.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(at) = reach.asked.iter().position(|asked| *asked == tx) {
                                reach.asked.swap_remove(at);
                                let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
                                reach.seen[usize::from(addr.is_ipv6())] = Some(addr);
                                drop(reach);
                                publish();
                            }
                        }
                        continue;
                    }
                    let out = lock(&server).handle_datagram(src, data, clock::now());
                    if let Some((to, datagram)) = out {
                        sockets.send(to, &datagram).await;
                    }
                }
            }));
        }
        // Housekeeping: endpoints that expire, and where the port is seen.
        {
            let (sockets, server, reach, shared) = (
                sockets.clone(),
                server.clone(),
                reach.clone(),
                self.shared.clone(),
            );
            tasks.push(tokio::spawn(async move {
                let mut expire = tokio::time::interval(EXPIRE_EVERY);
                let mut discover = tokio::time::interval(DISCOVER_EVERY);
                loop {
                    tokio::select! {
                        _ = expire.tick() => lock(&server).expire(clock::now()),
                        _ = discover.tick() => {
                            let targets: Vec<SocketAddr> = {
                                let state = shared.lock();
                                mesh_core::netcheck::targets(&state.netmap().derp_regions)
                                    .into_iter()
                                    .map(|(_, addr)| addr)
                                    .collect()
                            };
                            let mut asked = Vec::new();
                            for family_v6 in [false, true] {
                                for addr in targets.iter().filter(|a| a.is_ipv6() == family_v6).take(STUN_SERVERS) {
                                    let mut tx = [0u8; 12];
                                    mesh_core::random::fill(&mut tx);
                                    asked.push(tx);
                                    sockets.send(*addr, &stun::request(&tx)).await;
                                }
                            }
                            reach.lock().unwrap_or_else(|e| e.into_inner()).asked = asked;
                        }
                    }
                }
            }));
        }

        self.shared.set_relay(Some(server.clone()));
        tracing::info!("relaying UDP for peers on port {port}");
        Ok(PeerRelay {
            shared: self.shared.clone(),
            server,
            tasks,
            port,
        })
    }
}

/// The relay's port on `[::]` too, IPv6 only; `None` where there is none.
fn bind_v6(port: u16) -> Option<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    socket.set_only_v6(true).ok()?;
    socket.set_nonblocking(true).ok()?;
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())
        .ok()?;
    UdpSocket::from_std(socket.into()).ok()
}
