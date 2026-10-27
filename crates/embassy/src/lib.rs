//! arkitekt-mesh on embassy: a node of the deployment's tailnet without
//! std (docs/rfc9-sans-io-runtimes.md). The core (`mesh_core`) decides
//! everything; this crate moves its bytes over what the app gives it:
//!
//! - [`Udp`]: one IPv4 UDP socket (embassy-net's, on a board);
//! - [`Dial`]: byte streams to `host:port`, TLS or plain (the app's TLS:
//!   arkitekt-embassy's `conn::open`, on a board), for control and DERP.
//!
//! [`Mesh::run`] is the node: one future, for the app to run beside its
//! own (no `Send`, one executor). [`Mesh`] then connects TCP over the
//! tunnel ([`Mesh::connect`], and `embedded_nal_async::TcpConnect` and
//! `Dns` with the netmap's names), so anything on embedded-nal-async
//! reaches mesh services unchanged.
//!
//! Without std the app installs where randomness and the wall clock come
//! from first (`mesh_core::random::set_source`,
//! `mesh_core::time::set_wall_clock`).
//!
//! Every stream's `read` must be cancel-safe (embassy-net's TCP and TLS
//! over it are): a connection's loop waits on its read beside a timer and
//! its outgoing queue.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

mod control;
mod derp;
mod node;
mod tcp;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::net::SocketAddr;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embedded_io_async::{Read, Write};

pub use mesh_core;
use mesh_core::control::session::{ControlSession, SessionConfig, SessionError};
use mesh_core::control::types::{DerpRegion, Hostinfo};
use mesh_core::http2;
use mesh_core::keys::{NodePublic, PrivateKey};
use mesh_core::netstack::Congestion;
use mesh_core::node::{NodeCore, Settings};
use mesh_core::paths::Paths;
use mesh_core::time::{Duration, Instant};

pub use tcp::{TcpError, TcpStream};

/// The DERP connections at once: the home region's and one more.
pub const DERP_SLOTS: usize = 2;

/// One UDP socket, as the app has it.
pub trait Udp {
    type Error: core::fmt::Debug;
    async fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<(), Self::Error>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error>;
    /// The socket's port.
    fn local_port(&self) -> u16;
    /// This host's address on its default route with that port, if known:
    /// an endpoint for peers on the same network.
    fn local_endpoint(&self) -> Option<SocketAddr> {
        None
    }
}

/// How a stream is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls<'a> {
    /// Plain TCP (`http://` control, a test DERP).
    None,
    /// TLS with the server's certificate checked for this name.
    Verify(&'a str),
    /// TLS, the certificate unchecked: control (Noise authenticates it) and
    /// DERP servers marked insecure for tests or pinned.
    Unverified(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DialError(pub String);

/// Byte streams to `host:port` (an IP or a name), as the app makes them.
pub trait Dial {
    type Conn<'a>: Read + Write
    where
        Self: 'a;
    async fn dial<'a>(
        &'a self,
        host: &str,
        port: u16,
        tls: Tls<'_>,
    ) -> Result<Self::Conn<'a>, DialError>;

    /// Whether control and DERP go by WebSocket ([`websocket`](Self::websocket),
    /// [`get`](Self::get)) instead of HTTP upgrades on [`dial`](Self::dial)'s
    /// streams: a browser has no raw TCP.
    const WEBSOCKET: bool = false;

    /// A WebSocket to `url` (`ws://` or `wss://`) speaking `protocol`: each
    /// write goes as one binary message, reads give the messages' bytes.
    async fn websocket<'a>(
        &'a self,
        url: &str,
        protocol: &str,
    ) -> Result<Self::Conn<'a>, DialError> {
        let _ = (url, protocol);
        Err(DialError(String::from("this Dial has no WebSocket")))
    }

    /// `GET url`: its status and body (control's `/key`, by WebSocket).
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), DialError> {
        let _ = url;
        Err(DialError(String::from("this Dial has no GET")))
    }
}

/// Who the node is and how it runs.
#[derive(Clone)]
pub struct Config {
    /// `https://…` (or `http://…`, tests).
    pub control_url: String,
    pub machine_key: PrivateKey,
    pub node_key: PrivateKey,
    pub auth_key: Option<String>,
    pub hostname: String,
    pub tags: Vec<String>,
    pub ephemeral: bool,
    pub settings: Settings,
    /// Control's HTTP/2 windows: how much of a map response may be in us.
    pub http2: http2::Config,
    /// Packets queued per DERP connection.
    pub derp_queue: usize,
    /// Where the verified tailnet-lock chain is kept (flash, on a board).
    /// Without one, each start takes control's genesis again, so a
    /// compromised control could swap the trusted keys across a reboot.
    pub lock_store: Option<alloc::sync::Arc<dyn mesh_core::lock::LockStore>>,
}

impl Config {
    /// For a board (an ESP32-S3 with PSRAM, RFC-9's budget): small buffers
    /// and windows, direct paths over IPv4.
    pub fn small(control_url: String, machine_key: PrivateKey, node_key: PrivateKey) -> Self {
        Self {
            control_url,
            machine_key,
            node_key,
            auth_key: None,
            hostname: String::from("arkitekt-mesh-embassy"),
            tags: Vec::new(),
            ephemeral: false,
            settings: Settings {
                direct: true,
                ipv4: true,
                tcp_buffer: 16 << 10,
                listen_buffer: 16 << 10,
                tcp_buffer_max: 0,
                congestion: Congestion::Reno,
                handshake_queue: 8,
                max_active_peers: 8,
                udp_flows: 64,
                netcheck_interval: Some(Duration::from_secs(300)),
            },
            http2: http2::Config {
                stream_window: 16 << 10,
                connection_window: 16 << 10,
                header_table_size: 4096,
                max_header_list: 16 << 10,
            },
            derp_queue: 32,
            lock_store: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshError {
    #[error("{0}")]
    Control(#[from] SessionError),
    #[error("not an http(s) url: {0}")]
    Url(String),
}

/// A DERP slot: the region it should be connected to, packets for it.
#[derive(Default)]
struct Slot {
    /// The region, its description, whether it is home.
    region: Option<(i32, DerpRegion, bool)>,
    /// Bumped when the region changes: the connection made for an older
    /// one ends.
    generation: u32,
    queue: VecDeque<(NodePublic, Vec<u8>)>,
    up: bool,
}

/// Before the first netmap: what the start collects.
struct Start {
    paths: Option<Paths>,
    netmap: mesh_core::control::netmap::NetMap,
    filter_sets: alloc::collections::BTreeMap<String, Vec<mesh_core::filter::FilterRule>>,
    lock: mesh_core::lock::Lock,
}

struct Inner {
    core: Option<NodeCore>,
    start: Option<Start>,
    session: ControlSession,
    udp_out: VecDeque<(SocketAddr, Vec<u8>)>,
    slots: [Slot; DERP_SLOTS],
    /// Wakers of those waiting for the first netmap.
    joined: Vec<core::task::Waker>,
}

/// The node: shared by its tasks and the app's sockets (one executor).
pub struct Mesh {
    config: RefCell<Config>,
    inner: RefCell<Inner>,
    node_wake: Signal<NoopRawMutex, ()>,
    control_wake: Signal<NoopRawMutex, ()>,
    slot_wake: [Signal<NoopRawMutex, ()>; DERP_SLOTS],
}

/// The mesh's clock: embassy's, in the core's units.
pub(crate) fn now() -> Instant {
    Instant::from_micros(embassy_time::Instant::now().as_micros())
}

pub(crate) fn at(instant: Instant) -> embassy_time::Instant {
    embassy_time::Instant::from_micros(instant.as_micros())
}

impl Mesh {
    /// A node, not yet running ([`run`](Self::run)).
    pub fn new(config: Config) -> Self {
        Self {
            inner: RefCell::new(Self::fresh(&config)),
            config: RefCell::new(config),
            node_wake: Signal::new(),
            control_wake: Signal::new(),
            slot_wake: core::array::from_fn(|_| Signal::new()),
        }
    }

    /// Start over with `config`, in place, once [`run`](Self::run) ended
    /// (control refused the node, or could not be reached, before it
    /// joined): then run it again. A board makes one node and keeps it,
    /// instead of a new one for every attempt. Sockets of the old node are
    /// gone; it must not be running.
    pub fn restart(&self, config: Config) {
        *self.inner.borrow_mut() = Self::fresh(&config);
        *self.config.borrow_mut() = config;
    }

    /// The state of a node that has not started.
    fn fresh(config: &Config) -> Inner {
        let node_public = NodePublic(config.node_key.public());
        let mut paths = Paths::new(PrivateKey::generate(), node_public);
        paths.set_udp(config.settings.direct);
        let session = ControlSession::new(
            SessionConfig {
                node_key: node_public,
                disco_key: paths.disco_public(),
                hostinfo: Hostinfo {
                    ipn_version: String::from(concat!(
                        "arkitekt-mesh-embassy/",
                        env!("CARGO_PKG_VERSION")
                    )),
                    os: String::from("embassy"),
                    hostname: config.hostname.clone(),
                    app: String::from("arkitekt"),
                    request_tags: config.tags.clone(),
                    ..Default::default()
                },
                auth_key: config.auth_key.clone(),
                ephemeral: config.ephemeral,
            },
            String::new(),
            now(),
        );
        Inner {
            core: None,
            start: Some(Start {
                paths: Some(paths),
                netmap: Default::default(),
                filter_sets: Default::default(),
                lock: mesh_core::lock::Lock::new(config.lock_store.clone()),
            }),
            session,
            udp_out: VecDeque::new(),
            slots: Default::default(),
            joined: Vec::new(),
        }
    }

    /// The node's config (borrowed briefly: never across an await).
    pub(crate) fn config(&self) -> core::cell::Ref<'_, Config> {
        self.config.borrow()
    }

    /// Run the node: control, DERP and UDP, until control will not have it
    /// (before it first joined: refused, or unreachable).
    pub async fn run<U: Udp, D: Dial>(&self, udp: &U, dial: &D) -> Result<(), MeshError> {
        let url = control::Url::parse(&self.config().control_url)?;
        let derp = embassy_futures::join::join(self.slot_task(0, dial), self.slot_task(1, dial));
        match embassy_futures::select::select3(
            self.control_task(&url, dial),
            self.node_task(udp),
            derp,
        )
        .await
        {
            embassy_futures::select::Either3::First(result) => result,
            embassy_futures::select::Either3::Second(never) => match never {},
            embassy_futures::select::Either3::Third((never, _)) => match never {},
        }
    }

    /// Wait until the node has its first netmap (it is on the mesh).
    pub async fn joined(&self) {
        core::future::poll_fn(|cx| {
            let mut inner = self.inner.borrow_mut();
            if inner.core.is_some() {
                return core::task::Poll::Ready(());
            }
            inner.joined.push(cx.waker().clone());
            core::task::Poll::Pending
        })
        .await
    }

    /// Our tailnet addresses (empty until joined).
    pub fn addresses(&self) -> Vec<core::net::IpAddr> {
        let inner = self.inner.borrow();
        inner
            .core
            .as_ref()
            .map(|c| c.netmap().self_addresses().to_vec())
            .unwrap_or_default()
    }

    /// The direct UDP path to the peer at `ip`, if one is up (else its
    /// packets go through DERP).
    pub fn direct_path(&self, ip: core::net::IpAddr) -> Option<SocketAddr> {
        let inner = self.inner.borrow();
        let core = inner.core.as_ref()?;
        let key = core.netmap().peer_by_ip(ip)?.key;
        core.paths().direct(&key, now())
    }

    /// A peer's address by its name (`host` or `host.<tailnet domain>`), or
    /// an IP.
    pub fn resolve(&self, name: &str) -> Option<core::net::IpAddr> {
        if let Ok(ip) = name.parse() {
            return Some(ip);
        }
        let inner = self.inner.borrow();
        // A bare hostname, or one in the tailnet's domain: never another
        // domain's name that happens to start with a peer's.
        inner
            .core
            .as_ref()?
            .netmap()
            .peer_by_name(name.trim_start_matches('[').trim_end_matches(']'))?
            .primary_address()
    }
}
