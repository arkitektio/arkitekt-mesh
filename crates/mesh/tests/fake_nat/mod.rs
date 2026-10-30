//! A fake NAT gateway for the port-mapping tests: it answers PCP, NAT-PMP
//! or UPnP IGD (SSDP on its UDP socket, the description and SOAP control
//! over HTTP) on 127.0.0.1, and for each mapping binds a real "external"
//! socket on 127.0.0.2 that forwards datagrams both ways to the node's
//! internal port.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Speaks {
    Pcp,
    NatPmp,
    Upnp,
}

pub const EXTERNAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

#[derive(Default)]
pub struct Counters {
    pub maps: AtomicUsize,
    pub deletes: AtomicUsize,
    /// Datagrams forwarded from outside to the node.
    pub forwarded: AtomicUsize,
}

struct Mapping {
    external: SocketAddr,
    task: JoinHandle<()>,
}

struct State {
    epoch_base: std::time::Instant,
    mappings: HashMap<u16, Mapping>,
}

pub struct Gateway {
    pub addr: SocketAddr,
    pub counters: Arc<Counters>,
    lifetime: Arc<AtomicU32>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
    http: Option<JoinHandle<()>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(http) = &self.http {
            http.abort();
        }
        for m in self.state.lock().unwrap().mappings.values() {
            m.task.abort();
        }
    }
}

impl Gateway {
    pub async fn start(speaks: Speaks, lifetime: u32) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let counters = Arc::new(Counters::default());
        let lifetime = Arc::new(AtomicU32::new(lifetime));
        let state = Arc::new(Mutex::new(State {
            epoch_base: std::time::Instant::now(),
            mappings: HashMap::new(),
        }));
        let (http, location) = if speaks == Speaks::Upnp {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let location = format!("http://{}/rootDesc.xml", listener.local_addr().unwrap());
            let task = tokio::spawn(serve_http(
                listener,
                counters.clone(),
                lifetime.clone(),
                state.clone(),
            ));
            (Some(task), location)
        } else {
            (None, String::new())
        };
        let task = tokio::spawn(serve(
            socket,
            speaks,
            location,
            counters.clone(),
            lifetime.clone(),
            state.clone(),
        ));
        Self {
            addr,
            counters,
            lifetime,
            state,
            task,
            http,
        }
    }

    /// Forget every mapping and restart the epoch, as a rebooted router does.
    pub fn reboot(&self) {
        let mut state = self.state.lock().unwrap();
        for (_, m) in state.mappings.drain() {
            m.task.abort();
        }
        state.epoch_base = std::time::Instant::now();
    }

    /// The external address mapped to `internal`, if any.
    pub fn external(&self, internal: u16) -> Option<SocketAddr> {
        self.state
            .lock()
            .unwrap()
            .mappings
            .get(&internal)
            .map(|m| m.external)
    }

    pub fn externals(&self) -> Vec<SocketAddr> {
        self.state
            .lock()
            .unwrap()
            .mappings
            .values()
            .map(|m| m.external)
            .collect()
    }
}

async fn serve(
    socket: Arc<UdpSocket>,
    speaks: Speaks,
    location: String,
    counters: Arc<Counters>,
    lifetime: Arc<AtomicU32>,
    state: Arc<Mutex<State>>,
) {
    let mut buf = [0u8; 1100];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let req = buf[..n].to_vec();
        let epoch = state.lock().unwrap().epoch_base.elapsed().as_secs() as u32 + 1;
        let reply = match (speaks, req.first()) {
            (Speaks::Pcp, Some(2)) if req.len() >= 60 && req[1] == 1 => {
                let internal = u16::from_be_bytes([req[40], req[41]]);
                let asked = u32::from_be_bytes(req[4..8].try_into().unwrap());
                let (external, granted) = handle(&state, &counters, internal, 0, asked, &lifetime)
                    .await
                    .unwrap();
                let mut resp = req.clone();
                resp[1] = 0x81;
                resp[3] = 0;
                resp[4..8].copy_from_slice(&granted.to_be_bytes());
                resp[8..12].copy_from_slice(&epoch.to_be_bytes());
                resp[12..24].fill(0);
                resp[42..44].copy_from_slice(&external.port().to_be_bytes());
                resp[44..60].copy_from_slice(&EXTERNAL_IP.to_ipv6_mapped().octets());
                Some(resp)
            }
            (Speaks::NatPmp, Some(0)) if req.len() >= 2 && req[1] == 0 => {
                let mut resp = vec![0, 128, 0, 0];
                resp.extend_from_slice(&epoch.to_be_bytes());
                resp.extend_from_slice(&EXTERNAL_IP.octets());
                Some(resp)
            }
            (Speaks::NatPmp, Some(0)) if req.len() >= 12 && req[1] == 1 => {
                let internal = u16::from_be_bytes([req[4], req[5]]);
                let asked = u32::from_be_bytes(req[8..12].try_into().unwrap());
                let (external, granted) = handle(&state, &counters, internal, 0, asked, &lifetime)
                    .await
                    .unwrap();
                let mut resp = vec![0, 129, 0, 0];
                resp.extend_from_slice(&epoch.to_be_bytes());
                resp.extend_from_slice(&internal.to_be_bytes());
                resp.extend_from_slice(&external.port().to_be_bytes());
                resp.extend_from_slice(&granted.to_be_bytes());
                Some(resp)
            }
            (Speaks::Upnp, Some(b'M')) if req.starts_with(b"M-SEARCH") => Some(
                format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                     LOCATION: {location}\r\n\r\n"
                )
                .into_bytes(),
            ),
            // Not the protocol this gateway speaks: silence.
            _ => None,
        };
        if let Some(reply) = reply {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList>
</device></root>"#;

/// The UPnP gateway's HTTP side: its description, and SOAP control.
async fn serve_http(
    listener: TcpListener,
    counters: Arc<Counters>,
    lifetime: Arc<AtomicU32>,
    state: Arc<Mutex<State>>,
) {
    while let Ok((stream, _)) = listener.accept().await {
        let (counters, lifetime, state) = (counters.clone(), lifetime.clone(), state.clone());
        tokio::spawn(async move {
            let _ = answer(stream, &counters, &lifetime, &state).await;
        });
    }
}

async fn answer(
    mut stream: TcpStream,
    counters: &Arc<Counters>,
    lifetime: &AtomicU32,
    state: &Arc<Mutex<State>>,
) -> std::io::Result<()> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let request = loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let Some(end) = text.find("\r\n\r\n") else {
            continue;
        };
        let length = text[..end]
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if raw.len() >= end + 4 + length {
            break text;
        }
    };
    let field = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let start = request.find(&open)? + open.len();
        let len = request[start..].find('<')?;
        Some(request[start..start + len].to_owned())
    };
    let ok = |action: &str, fields: String| {
        format!(
            "<s:Envelope><s:Body><u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{fields}</u:{action}Response></s:Body></s:Envelope>"
        )
    };
    let fault = |code: u16| {
        format!(
            "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        )
    };
    let (status, body) = if request.starts_with("GET /rootDesc.xml") {
        (200, DESCRIPTION.to_owned())
    } else if request.contains("#GetExternalIPAddress") {
        let ip = format!("<NewExternalIPAddress>{EXTERNAL_IP}</NewExternalIPAddress>");
        (200, ok("GetExternalIPAddress", ip))
    } else if request.contains("#AddPortMapping") {
        let port = |name| field(name).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
        let (external, internal) = (port("NewExternalPort"), port("NewInternalPort"));
        // UPnP's lease 0 is "until deleted", not a delete.
        let lease = field("NewLeaseDuration")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|l| *l != 0)
            .unwrap_or(u32::MAX);
        match handle(state, counters, internal, external, lease, lifetime).await {
            Some(_) => (200, ok("AddPortMapping", String::new())),
            None => (500, fault(718)),
        }
    } else if request.contains("#DeletePortMapping") {
        let external = field("NewExternalPort").and_then(|v| v.parse::<u16>().ok());
        let internal = state
            .lock()
            .unwrap()
            .mappings
            .iter()
            .find(|(_, m)| Some(m.external.port()) == external)
            .map(|(internal, _)| *internal);
        match internal {
            Some(internal) => {
                handle(state, counters, internal, 0, 0, lifetime).await;
                (200, ok("DeletePortMapping", String::new()))
            }
            None => (500, fault(714)),
        }
    } else {
        (404, String::new())
    };
    let reason = if status == 200 { "OK" } else { "Error" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Map (or delete, lifetime 0) `internal`, at external port `want` if not
/// 0; returns its external address and the lifetime granted, or `None` if
/// `want` is taken.
async fn handle(
    state: &Arc<Mutex<State>>,
    counters: &Arc<Counters>,
    internal: u16,
    want: u16,
    asked: u32,
    lifetime: &AtomicU32,
) -> Option<(SocketAddr, u32)> {
    if asked == 0 {
        counters.deletes.fetch_add(1, Ordering::Relaxed);
        let removed = state.lock().unwrap().mappings.remove(&internal);
        let external = removed.map(|m| {
            m.task.abort();
            m.external
        });
        return Some((external.unwrap_or(SocketAddr::from((EXTERNAL_IP, 0))), 0));
    }
    counters.maps.fetch_add(1, Ordering::Relaxed);
    if let Some(m) = state.lock().unwrap().mappings.get(&internal) {
        return Some((m.external, lifetime.load(Ordering::Relaxed).min(asked)));
    }
    let outside = UdpSocket::bind((EXTERNAL_IP, want)).await.ok()?;
    let external = outside.local_addr().unwrap();
    let inside = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, internal));
    let forwarded = counters.clone();
    let task = tokio::spawn(async move {
        let (mut a, mut b) = ([0u8; 2048], [0u8; 2048]);
        let mut remote: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                Ok((n, from)) = outside.recv_from(&mut a) => {
                    remote = Some(from);
                    forwarded.forwarded.fetch_add(1, Ordering::Relaxed);
                    let _ = inside.send_to(&a[..n], target).await;
                }
                Ok((n, _)) = inside.recv_from(&mut b) => {
                    if let Some(to) = remote {
                        let _ = outside.send_to(&b[..n], to).await;
                    }
                }
            }
        }
    });
    state
        .lock()
        .unwrap()
        .mappings
        .insert(internal, Mapping { external, task });
    Some((external, lifetime.load(Ordering::Relaxed).min(asked)))
}
