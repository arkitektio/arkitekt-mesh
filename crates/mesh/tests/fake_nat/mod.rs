//! A fake NAT gateway for the port-mapping tests: it answers PCP or NAT-PMP
//! on 127.0.0.1, and for each mapping binds a real "external" socket on
//! 127.0.0.2 that forwards datagrams both ways to the node's internal port.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Speaks {
    Pcp,
    NatPmp,
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
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
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
        let task = tokio::spawn(serve(
            socket,
            speaks,
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
                let (external, granted) =
                    handle(&state, &counters, internal, asked, &lifetime).await;
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
                let (external, granted) =
                    handle(&state, &counters, internal, asked, &lifetime).await;
                let mut resp = vec![0, 129, 0, 0];
                resp.extend_from_slice(&epoch.to_be_bytes());
                resp.extend_from_slice(&internal.to_be_bytes());
                resp.extend_from_slice(&external.port().to_be_bytes());
                resp.extend_from_slice(&granted.to_be_bytes());
                Some(resp)
            }
            // Not the protocol this gateway speaks: silence.
            _ => None,
        };
        if let Some(reply) = reply {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

/// Map (or delete, lifetime 0) `internal`; returns its external address and
/// the lifetime granted.
async fn handle(
    state: &Arc<Mutex<State>>,
    counters: &Arc<Counters>,
    internal: u16,
    asked: u32,
    lifetime: &AtomicU32,
) -> (SocketAddr, u32) {
    if asked == 0 {
        counters.deletes.fetch_add(1, Ordering::Relaxed);
        let removed = state.lock().unwrap().mappings.remove(&internal);
        let external = removed.map(|m| {
            m.task.abort();
            m.external
        });
        return (external.unwrap_or(SocketAddr::from((EXTERNAL_IP, 0))), 0);
    }
    counters.maps.fetch_add(1, Ordering::Relaxed);
    if let Some(m) = state.lock().unwrap().mappings.get(&internal) {
        return (m.external, lifetime.load(Ordering::Relaxed).min(asked));
    }
    let outside = UdpSocket::bind((EXTERNAL_IP, 0)).await.unwrap();
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
    (external, lifetime.load(Ordering::Relaxed).min(asked))
}
