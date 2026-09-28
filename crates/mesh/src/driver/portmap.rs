//! Keeping a port mapping on the gateway (docs/rfc3-nat-port-mapping.md).
//!
//! A task of its own, with its own socket: nothing on the node's hot path
//! waits for a gateway that may never answer. It maps the node's UDP port
//! (PCP, else NAT-PMP), renews at half the lifetime, maps again when the
//! port changes or the gateway's epoch goes backwards (it rebooted), and
//! deletes the mapping, best effort, when the node goes away. The mapped
//! address is published to the node, which reports it as a `Portmapped`
//! endpoint.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use super::node::Shared;
use crate::portmap::{self, Mapping, LIFETIME};

/// Test-only: the gateway to use (`ip:port`) instead of the default route's.
pub const GATEWAY_ENV: &str = "ARKITEKT_MESH_PORTMAP_GATEWAY";

const ATTEMPTS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(500)];
const RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Pcp { nonce: [u8; 12] },
    NatPmp,
}

fn gateway() -> Option<SocketAddr> {
    if let Some(addr) = std::env::var(GATEWAY_ENV).ok().and_then(|v| v.parse().ok()) {
        return Some(addr);
    }
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let gw = portmap::linux_default_gateway(&table)?;
        return Some(SocketAddr::new(IpAddr::V4(gw), portmap::PORT));
    }
    #[allow(unreachable_code)]
    None
}

/// One request, retried briefly; the first datagram that parses answers it.
async fn ask<T>(
    socket: &UdpSocket,
    request: &[u8],
    mut parse: impl FnMut(&[u8]) -> Result<T, portmap::PortmapError>,
) -> Option<Result<T, portmap::PortmapError>> {
    let mut buf = [0u8; 1100];
    for wait in ATTEMPTS {
        socket.send(request).await.ok()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => match parse(&buf[..n]) {
                    Err(portmap::PortmapError::Malformed | portmap::PortmapError::Mismatch) => {
                        continue
                    }
                    other => return Some(other),
                },
                Ok(Err(_)) => return None,
                Err(_) => break,
            }
        }
    }
    None
}

async fn map(
    socket: &UdpSocket,
    internal: u16,
    protocol: Option<Protocol>,
    lifetime: u32,
) -> Option<(Protocol, Mapping)> {
    let client = socket.local_addr().ok()?.ip();
    // PCP first (unless NAT-PMP is what worked before).
    if !matches!(protocol, Some(Protocol::NatPmp)) {
        let nonce = match protocol {
            Some(Protocol::Pcp { nonce }) => nonce,
            _ => {
                let mut nonce = [0u8; 12];
                OsRng.fill_bytes(&mut nonce);
                nonce
            }
        };
        let req = portmap::pcp_map_request(client, internal, None, lifetime, &nonce);
        match ask(socket, &req, |r| {
            portmap::pcp_parse_map(r, internal, &nonce)
        })
        .await
        {
            Some(Ok(m)) => return Some((Protocol::Pcp { nonce }, m)),
            Some(Err(e)) => tracing::debug!("PCP: {e}"),
            None => {}
        }
    }
    let (public, _) = ask(socket, &portmap::natpmp_external_address_request(), |r| {
        portmap::natpmp_parse_external_address(r)
    })
    .await?
    .map_err(|e| tracing::debug!("NAT-PMP: {e}"))
    .ok()?;
    let req = portmap::natpmp_map_request(internal, 0, lifetime);
    match ask(socket, &req, |r| {
        portmap::natpmp_parse_map(r, internal, public)
    })
    .await?
    {
        Ok(m) => Some((Protocol::NatPmp, m)),
        Err(e) => {
            tracing::debug!("NAT-PMP: {e}");
            None
        }
    }
}

/// Deletes the mapping when dropped (the task is aborted with its node).
struct Held {
    gateway: SocketAddr,
    internal: u16,
    protocol: Protocol,
}

impl Drop for Held {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (gateway, internal, protocol) = (self.gateway, self.internal, self.protocol);
        runtime.spawn(async move {
            let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
                return;
            };
            if socket.connect(gateway).await.is_err() {
                return;
            }
            let _ = map(&socket, internal, Some(protocol), 0).await;
        });
    }
}

fn publish(shared: &Shared, external: Option<SocketAddr>) {
    let mut state = shared.lock();
    if state.portmap_endpoint != external {
        state.portmap_endpoint = external;
        drop(state);
        shared.wake.notify_one();
    }
}

pub(super) async fn run(shared: Arc<Shared>, mut port: watch::Receiver<u16>) {
    let Some(gateway) = gateway() else {
        tracing::debug!("port mapping: no default gateway found");
        return;
    };
    let mut held: Option<Held> = None;
    let mut last_epoch: Option<u32> = None;
    let mut retry = RETRY;
    loop {
        let internal = *port.borrow_and_update();
        if held.as_ref().is_some_and(|h| h.internal != internal) {
            // The node rebound: the old mapping points nowhere.
            held = None;
            last_epoch = None;
        }
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) if s.connect(gateway).await.is_ok() => s,
            _ => {
                tokio::time::sleep(retry).await;
                continue;
            }
        };
        let protocol = held.as_ref().map(|h| h.protocol);
        let wait = match map(&socket, internal, protocol, LIFETIME).await {
            Some((protocol, mapping)) => {
                if last_epoch.is_some_and(|e| mapping.epoch < e) {
                    tracing::info!("port mapping: the gateway restarted; mapped again");
                }
                last_epoch = Some(mapping.epoch);
                if held.is_none() {
                    tracing::info!(
                        "port mapping: {} -> :{internal} ({protocol:?})",
                        mapping.external
                    );
                }
                // Keep the old guard (its delete would undo this mapping).
                match &mut held {
                    Some(h) => h.protocol = protocol,
                    None => {
                        held = Some(Held {
                            gateway,
                            internal,
                            protocol,
                        })
                    }
                }
                publish(&shared, Some(mapping.external));
                retry = RETRY;
                Duration::from_secs((mapping.lifetime / 2).max(1) as u64)
            }
            None => {
                // No delete: the gateway is not answering anyway.
                if let Some(h) = held.take() {
                    tracing::info!("port mapping: the gateway stopped answering");
                    std::mem::forget(h);
                }
                publish(&shared, None);
                let wait = retry;
                retry = (retry * 2).min(MAX_RETRY);
                wait
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = port.changed() => if changed.is_err() { return },
        }
    }
}
