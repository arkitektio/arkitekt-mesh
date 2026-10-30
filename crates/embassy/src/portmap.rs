//! Keeping a port mapping on the LAN's gateway (docs/rfc3-nat-port-mapping.md),
//! as the tokio driver does: PCP, else NAT-PMP, else UPnP IGD, renewed at
//! half the lifetime, the mapped address published to the node as a
//! `Portmapped` endpoint. A future of its own with its own socket, so the
//! node never waits for a gateway that may not answer. No delete when it
//! stops: a board just goes, and the mapping runs out.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use embassy_time::{with_timeout, Duration, Instant, Timer};
use embedded_io_async::{Read, Write};
use mesh_core::portmap::upnp::{self, Control, Url};
use mesh_core::portmap::{self, Mapping, PortmapError, LIFETIME};

use crate::{Dial, Mesh, Tls, Udp};

const ATTEMPTS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(500)];
const RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(10 * 60);
/// A UPnP request and its response, at most.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// Where the node is on its LAN, from the app's network stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lan {
    /// This host's address.
    pub address: Ipv4Addr,
    /// The default route's gateway: who is asked for the mapping.
    pub gateway: Ipv4Addr,
    /// The node's UDP port (its [`Udp::local_port`]), the one mapped.
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Protocol {
    Pcp { nonce: [u8; 12] },
    NatPmp,
    Upnp { control: Control, external: u16 },
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

impl Mesh {
    /// Keep a port mapping for the node on `lan`'s gateway, over `udp` (a
    /// socket of its own, not the node's) and `dial` (plain TCP to the
    /// gateway, for UPnP). Run it beside [`run`](Self::run); it never ends.
    /// Without a gateway that maps (a campus network), it asks again now
    /// and then, quietly.
    pub async fn portmap<U: Udp, D: Dial>(
        &self,
        udp: &U,
        dial: &D,
        lan: Lan,
    ) -> core::convert::Infallible {
        self.joined().await;
        let mut held: Option<Protocol> = None;
        let mut last_epoch: Option<u32> = None;
        let mut retry = RETRY;
        loop {
            let wait = match map(udp, dial, lan, held.take()).await {
                Some((protocol, mapping)) => {
                    if last_epoch.is_some_and(|e| mapping.epoch < e) {
                        tracing::info!("port mapping: the gateway restarted; mapped again");
                    }
                    last_epoch = Some(mapping.epoch);
                    if self.portmapped() != Some(mapping.external) {
                        tracing::info!(
                            "port mapping: {} -> :{} ({})",
                            mapping.external,
                            lan.port,
                            protocol.name()
                        );
                    }
                    held = Some(protocol);
                    self.publish(Some(mapping.external));
                    retry = RETRY;
                    Duration::from_secs(u64::from((mapping.lifetime / 2).max(1)))
                }
                None => {
                    if self.portmapped().is_some() {
                        tracing::info!("port mapping: the gateway stopped answering");
                    } else {
                        tracing::debug!("port mapping: no gateway mapped the port");
                    }
                    last_epoch = None;
                    self.publish(None);
                    let wait = retry;
                    retry = (retry * 2).min(MAX_RETRY);
                    wait
                }
            };
            Timer::after(wait).await;
        }
    }

    fn portmapped(&self) -> Option<SocketAddr> {
        self.inner.borrow().core.as_ref()?.portmap_endpoint()
    }

    fn publish(&self, external: Option<SocketAddr>) {
        let changed = {
            let mut inner = self.inner.borrow_mut();
            match inner.core.as_mut() {
                Some(core) if core.portmap_endpoint() != external => {
                    core.set_portmap_endpoint(external);
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.node_wake.signal(());
        }
    }
}

/// One request to `to`, retried briefly; the first datagram from it that
/// parses answers it.
async fn ask<U: Udp, T>(
    udp: &U,
    to: SocketAddr,
    request: &[u8],
    mut parse: impl FnMut(&[u8]) -> Result<T, PortmapError>,
) -> Option<Result<T, PortmapError>> {
    let mut buf = vec![0u8; 1100];
    for wait in ATTEMPTS {
        udp.send_to(request, to).await.ok()?;
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match with_timeout(left, udp.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == to => match parse(&buf[..n]) {
                    Err(PortmapError::Malformed | PortmapError::Mismatch) => continue,
                    other => return Some(other),
                },
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return None,
                Err(_) => break,
            }
        }
    }
    None
}

/// What worked before first; else PCP, NAT-PMP and UPnP in turn.
async fn map<U: Udp, D: Dial>(
    udp: &U,
    dial: &D,
    lan: Lan,
    before: Option<Protocol>,
) -> Option<(Protocol, Mapping)> {
    if let Some(Protocol::Upnp { control, external }) = &before {
        if let Some(found) = upnp_map(dial, lan, control.clone(), Some(*external)).await {
            return Some(found);
        }
    }
    let gateway = SocketAddr::new(IpAddr::V4(lan.gateway), portmap::PORT);
    if !matches!(before, Some(Protocol::NatPmp)) {
        let nonce = match before {
            Some(Protocol::Pcp { nonce }) => nonce,
            _ => {
                let mut nonce = [0u8; 12];
                mesh_core::random::fill(&mut nonce);
                nonce
            }
        };
        let client = IpAddr::V4(lan.address);
        let req = portmap::pcp_map_request(client, lan.port, None, LIFETIME, &nonce);
        match ask(udp, gateway, &req, |r| {
            portmap::pcp_parse_map(r, lan.port, &nonce)
        })
        .await
        {
            Some(Ok(m)) => return Some((Protocol::Pcp { nonce }, m)),
            Some(Err(e)) => tracing::debug!("PCP: {e}"),
            None => {}
        }
    }
    if let Some(found) = natpmp(udp, gateway, lan.port).await {
        return Some(found);
    }
    let control = discover(udp, dial, lan.gateway).await?;
    upnp_map(dial, lan, control, None).await
}

async fn natpmp<U: Udp>(
    udp: &U,
    gateway: SocketAddr,
    internal: u16,
) -> Option<(Protocol, Mapping)> {
    let request = portmap::natpmp_external_address_request();
    let (public, _) = ask(
        udp,
        gateway,
        &request,
        portmap::natpmp_parse_external_address,
    )
    .await?
    .map_err(|e| tracing::debug!("NAT-PMP: {e}"))
    .ok()?;
    let request = portmap::natpmp_map_request(internal, 0, LIFETIME);
    match ask(udp, gateway, &request, |r| {
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
async fn http<D: Dial>(dial: &D, url: &Url, request: &[u8]) -> Option<(u16, Vec<u8>)> {
    let exchange = async {
        let mut conn = dial.dial(&url.host, url.port, Tls::None).await.ok()?;
        conn.write_all(request).await.ok()?;
        conn.flush().await.ok()?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 1024];
        while !upnp::http_complete(&raw) && raw.len() <= upnp::MAX_RESPONSE {
            match conn.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                // A server closing abruptly once it sent everything.
                Err(_) if !raw.is_empty() => break,
                Err(_) => return None,
            }
        }
        upnp::http_response(&raw)
            .map_err(|e| tracing::debug!("UPnP: {}: {e}", url.path))
            .ok()
    };
    with_timeout(HTTP_TIMEOUT, exchange).await.ok()?
}

/// The gateway's port-mapping service: an SSDP search (to the gateway,
/// and the multicast group), then its description.
async fn discover<U: Udp, D: Dial>(udp: &U, dial: &D, gateway: Ipv4Addr) -> Option<Control> {
    let targets = [
        SocketAddr::new(IpAddr::V4(gateway), upnp::SSDP_PORT),
        upnp::SSDP_MULTICAST,
    ];
    let mut buf = vec![0u8; 1500];
    for wait in ATTEMPTS {
        for target in targets {
            for device in upnp::GATEWAYS {
                let _ = udp.send_to(&upnp::ssdp_search(device), target).await;
            }
        }
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(Ok((n, _))) = with_timeout(left, udp.recv_from(&mut buf)).await else {
                break;
            };
            let Some(location) = upnp::ssdp_location(&buf[..n]) else {
                continue;
            };
            let Some((200, body)) = http(dial, &location, &upnp::http_get(&location)).await else {
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

/// Map the node's port with UPnP: at `external` (what the gateway gave
/// before), else at the same port, else at random ones if those are taken.
async fn upnp_map<D: Dial>(
    dial: &D,
    lan: Lan,
    control: Control,
    external: Option<u16>,
) -> Option<(Protocol, Mapping)> {
    let (status, body) = http(dial, &control.url, &upnp::get_external_ip(&control)).await?;
    let public = upnp::parse_external_ip(status, &body)
        .map_err(|e| tracing::debug!("UPnP: {e}"))
        .ok()?;
    if !upnp::is_public(public) {
        tracing::debug!("UPnP: the gateway is behind another NAT ({public})");
        return None;
    }
    let random = || 1024 + (mesh_core::random::u32() % (65536 - 1024)) as u16;
    let mut tries = vec![external.unwrap_or(lan.port), random(), random()];
    tries.dedup();
    let mut port = tries.remove(0);
    let mut lease = LIFETIME;
    loop {
        let request = upnp::add_port_mapping(&control, port, lan.port, lan.address, lease);
        let (status, body) = http(dial, &control.url, &request).await?;
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
