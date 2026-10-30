//! Keeping a port mapping on the gateway (docs/rfc3-nat-port-mapping.md).
//!
//! A task of its own, with its own socket: nothing on the node's hot path
//! waits for a gateway that may never answer. It maps the node's UDP port
//! (PCP, else NAT-PMP, else UPnP IGD), renews at half the lifetime, maps
//! again when the port changes or the gateway's epoch goes backwards (it
//! rebooted), and deletes the mapping, best effort, when the node goes
//! away. The mapped address is published to the node, which reports it as
//! a `Portmapped` endpoint.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use super::node::Shared;
use crate::portmap::upnp::{self, Control, Url};
use crate::portmap::{self, Mapping, LIFETIME};

/// Test-only: the gateway to use (`ip:port`) instead of the default route's.
pub const GATEWAY_ENV: &str = "ARKITEKT_MESH_PORTMAP_GATEWAY";
/// Test-only: where SSDP searches go (`ip:port`), instead of the gateway's
/// port 1900 and the multicast group.
pub const SSDP_ENV: &str = "ARKITEKT_MESH_PORTMAP_SSDP";
/// A UPnP request and its response, at most.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

const ATTEMPTS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(500)];
const RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Protocol {
    Pcp {
        nonce: [u8; 12],
    },
    NatPmp,
    /// The gateway's control URL and the external port it gave.
    Upnp {
        control: Control,
        external: u16,
    },
}

impl Protocol {
    fn name(&self) -> &'static str {
        match self {
            Protocol::Pcp { .. } => "PCP",
            Protocol::NatPmp => "NAT-PMP",
            Protocol::Upnp { .. } => "UPnP",
        }
    }
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
    // What worked before, first; else PCP, NAT-PMP and UPnP in turn.
    if let Some(Protocol::Upnp { control, external }) = &protocol {
        if let Some(found) = upnp_map(control.clone(), Some(*external), client, internal).await {
            return Some(found);
        }
    }
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
    if let Some(found) = natpmp(socket, internal, lifetime).await {
        return Some(found);
    }
    // A delete by lifetime 0 is PCP's and NAT-PMP's; UPnP's is `unmap`'s.
    if lifetime == 0 {
        return None;
    }
    let gateway = socket.peer_addr().ok()?.ip();
    let control = discover(gateway).await?;
    upnp_map(control, None, client, internal).await
}

async fn natpmp(socket: &UdpSocket, internal: u16, lifetime: u32) -> Option<(Protocol, Mapping)> {
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

/// One HTTP exchange with the gateway: the response's status and body.
async fn http(url: &Url, request: &[u8]) -> Option<(u16, Vec<u8>)> {
    let exchange = async {
        let mut stream = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .ok()?;
        stream.write_all(request).await.ok()?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        while !upnp::http_complete(&raw) && raw.len() <= upnp::MAX_RESPONSE {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        upnp::http_response(&raw)
            .map_err(|e| tracing::debug!("UPnP: {}: {e}", url.path))
            .ok()
    };
    tokio::time::timeout(HTTP_TIMEOUT, exchange).await.ok()?
}

/// The gateway's port-mapping service: an SSDP search (to the gateway,
/// and the multicast group), then its description.
async fn discover(gateway: IpAddr) -> Option<Control> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let targets = match std::env::var(SSDP_ENV).ok().and_then(|v| v.parse().ok()) {
        Some(addr) => vec![addr],
        None => vec![
            SocketAddr::new(gateway, upnp::SSDP_PORT),
            upnp::SSDP_MULTICAST,
        ],
    };
    let mut buf = [0u8; 1500];
    for wait in ATTEMPTS {
        for target in &targets {
            for device in upnp::GATEWAYS {
                let _ = socket.send_to(&upnp::ssdp_search(device), target).await;
            }
        }
        let deadline = tokio::time::Instant::now() + wait;
        while let Ok(Ok((n, _))) =
            tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        {
            let Some(location) = upnp::ssdp_location(&buf[..n]) else {
                continue;
            };
            let Some((200, body)) = http(&location, &upnp::http_get(&location)).await else {
                continue;
            };
            match upnp::control_url(&String::from_utf8_lossy(&body), &location) {
                Some(control) => return Some(control),
                None => tracing::debug!("UPnP: no WAN connection service at {}", location.path),
            }
        }
    }
    None
}

/// Map `internal` with UPnP: at `external` (what the gateway gave before),
/// else at the same port, else at random ones if those are taken.
async fn upnp_map(
    control: Control,
    external: Option<u16>,
    client: IpAddr,
    internal: u16,
) -> Option<(Protocol, Mapping)> {
    let IpAddr::V4(client) = client else {
        return None;
    };
    let (status, body) = http(&control.url, &upnp::get_external_ip(&control)).await?;
    let public = upnp::parse_external_ip(status, &body)
        .map_err(|e| tracing::debug!("UPnP: {e}"))
        .ok()?;
    if !upnp::is_public(public) {
        tracing::debug!("UPnP: the gateway is behind another NAT ({public})");
        return None;
    }
    let random = || 1024 + (OsRng.next_u32() % (65536 - 1024)) as u16;
    let mut lease = LIFETIME;
    let mut tries = vec![external.unwrap_or(internal), random(), random()];
    tries.dedup();
    let mut port = tries.remove(0);
    loop {
        let request = upnp::add_port_mapping(&control, port, internal, client, lease);
        let (status, body) = http(&control.url, &request).await?;
        match upnp::soap_result(status, &body) {
            Ok(()) => {
                let mapping = Mapping {
                    external: SocketAddr::new(IpAddr::V4(public), port),
                    lifetime: LIFETIME,
                    // UPnP has no epoch: renewals map again anyway.
                    epoch: 0,
                };
                return Some((
                    Protocol::Upnp {
                        control,
                        external: port,
                    },
                    mapping,
                ));
            }
            Err(upnp::UpnpError::Fault(upnp::ONLY_PERMANENT)) if lease != 0 => lease = 0,
            Err(upnp::UpnpError::Fault(upnp::CONFLICT)) if !tries.is_empty() => {
                port = tries.remove(0);
            }
            Err(e) => {
                tracing::debug!("UPnP: AddPortMapping: {e}");
                return None;
            }
        }
    }
}

/// Undo a mapping: lifetime 0 for PCP and NAT-PMP, a delete for UPnP.
async fn unmap(gateway: SocketAddr, internal: u16, protocol: Protocol) {
    if let Protocol::Upnp { control, external } = &protocol {
        let _ = http(&control.url, &upnp::delete_port_mapping(control, *external)).await;
        return;
    }
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return;
    };
    if socket.connect(gateway).await.is_err() {
        return;
    }
    let _ = map(&socket, internal, Some(protocol), 0).await;
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
        let (gateway, internal, protocol) = (self.gateway, self.internal, self.protocol.clone());
        runtime.spawn(unmap(gateway, internal, protocol));
    }
}

fn publish(shared: &Shared, external: Option<SocketAddr>) {
    let mut state = shared.lock();
    if state.portmap_endpoint() != external {
        state.set_portmap_endpoint(external);
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
        let protocol = held.as_ref().map(|h| h.protocol.clone());
        let wait = match map(&socket, internal, protocol, LIFETIME).await {
            Some((protocol, mapping)) => {
                if last_epoch.is_some_and(|e| mapping.epoch < e) {
                    tracing::info!("port mapping: the gateway restarted; mapped again");
                }
                last_epoch = Some(mapping.epoch);
                if held.is_none() {
                    tracing::info!(
                        "port mapping: {} -> :{internal} ({})",
                        mapping.external,
                        protocol.name()
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
