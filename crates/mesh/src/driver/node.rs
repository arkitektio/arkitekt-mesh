//! A running mesh node: control, DERP, a UDP socket, WireGuard and the
//! netstack, driven by one loop that owns the state.
//!
//! App sockets ([`TcpStream`]) share the state behind a mutex; they wake
//! the loop after every read and write, and smoltcp wakes them back.

use std::collections::{BTreeMap, HashMap};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use mesh_core::time as clock;

use mesh_core::tcpip::iface::SocketHandle;
use mesh_core::tcpip::socket::tcp::State as TcpState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use super::control::ControlError;
use super::control_link::{ControlLink, Out};
use super::derp::{self as derp_conn, Received};
use crate::control::netmap::NetMap;
use crate::control::types::{EndpointType, MapResponse};
use crate::derp;
use crate::keys::{NodeIdentity, PrivateKey};
use crate::netstack;
use crate::paths::{Paths, Via};
use crate::wg;
use mesh_core::node::{canonical, Event, HomeReport, NodeCore, Settings};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the node may take to register and get its first netmap.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// How to join the mesh.
#[derive(Debug, Clone)]
pub struct Config {
    pub control_url: String,
    pub identity: NodeIdentity,
    /// Needed the first time a node key registers.
    pub auth_key: Option<String>,
    pub hostname: String,
    pub ephemeral: bool,
    pub tags: Vec<String>,
    /// Try direct UDP paths (disco); off means DERP only.
    pub direct: bool,
    /// Buffer and queue sizes.
    pub limits: Limits,
}

/// Buffer and queue sizes: memory against throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// TCP buffer per socket, each way: also the most a connection has in
    /// flight, so its throughput is at most this per round trip (64 KiB
    /// at 20 ms is 3 MiB/s, 1 MiB is 50; measured in
    /// docs/rfc7-production-and-throughput.md).
    pub tcp_buffer: usize,
    /// TCP buffer, each way, of listening sockets (allocated while they
    /// wait) and the connections they accept.
    pub listen_buffer: usize,
    /// How far the TCP receive buffers grow, all together, from the sizes
    /// above, while their applications read what arrives (receive buffer
    /// auto-tuning, feature `fast-tcp`; 0: never): one stream may take it
    /// all, several share it. More than the UDP buffer takes in a burst is
    /// dropped. tailscale's netstack allows 8 MiB a connection.
    pub tcp_buffer_max: usize,
    /// How far a TCP transmit buffer grows while the path takes more than
    /// it holds (`fast-tcp`; 0: never, the default). Off until smoltcp
    /// retransmits selectively: with megabytes in flight, one loss has it
    /// send them all again (8 streams at 20 ms in the lab: 230 -> 9 MiB/s).
    pub tcp_send_buffer_max: usize,
    /// How TCP senders hold back on loss.
    pub congestion: netstack::Congestion,
    /// Packets queued per DERP connection (and from all of DERP to the node).
    pub derp_queue: usize,
    /// Packets sent to a DERP server back to back before a millisecond's
    /// pause (0: no pauses): a relay drops what it cannot pass on at once.
    pub derp_burst: usize,
    /// The UDP port to take, if it is free (0: any). A node that comes
    /// back on the port it had is where its peers still send: they trust
    /// a direct path for seconds after its last answer.
    pub udp_port: u16,
    /// The UDP sockets' kernel buffers, each way (0: the system's default,
    /// which a burst at a few hundred Mbit/s overflows). The system may
    /// allow less (`net.core.rmem_max` on Linux).
    pub udp_buffer: usize,
    /// Packets held per peer while a handshake is in flight.
    pub handshake_queue: usize,
    /// Peers with WireGuard and path state at once (0: no limit). Past it,
    /// the least recently used lose theirs (and redo a handshake when next
    /// used); the priority peer ([`Node::set_priority_peer`]) never does.
    pub max_active_peers: usize,
    /// UDP flows we started whose replies the packet filter lets in without
    /// a rule (the oldest are forgotten past it).
    pub udp_flows: usize,
    /// How often to measure every DERP region's latency and re-pick the home
    /// region (`None`: once, at start).
    pub netcheck_interval: Option<Duration>,
    /// Direct paths over IPv4 and over IPv6 (docs/rfc2-ipv6-underlay.md).
    /// IPv6 costs a second UDP socket; without it (or where it cannot be
    /// bound) the node runs over IPv4 alone.
    pub ipv4: bool,
    pub ipv6: bool,
    /// Ask the gateway for a port mapping (feature `portmap`;
    /// docs/rfc3-nat-port-mapping.md).
    pub portmap: bool,
}

impl Default for Limits {
    /// For desktops and servers.
    fn default() -> Self {
        Self {
            tcp_buffer: 1 << 20,
            listen_buffer: netstack::TCP_BUFFER,
            tcp_buffer_max: 8 << 20,
            tcp_send_buffer_max: 0,
            congestion: netstack::Congestion::Cubic,
            derp_queue: 1024,
            derp_burst: 32,
            udp_port: 0,
            udp_buffer: 4 << 20,
            handshake_queue: wg::MAX_QUEUED,
            max_active_peers: 0,
            udp_flows: 1024,
            netcheck_interval: Some(Duration::from_secs(5 * 60)),
            ipv4: true,
            ipv6: true,
            portmap: true,
        }
    }
}

impl Limits {
    /// For microcontrollers: small buffers, short queues.
    pub fn small() -> Self {
        Self {
            tcp_buffer: 8 * 1024,
            listen_buffer: 4 * 1024,
            tcp_buffer_max: 0,
            tcp_send_buffer_max: 0,
            congestion: netstack::Congestion::None,
            derp_queue: 32,
            derp_burst: 0,
            udp_port: 0,
            udp_buffer: 0,
            handshake_queue: 8,
            max_active_peers: 16,
            udp_flows: 32,
            netcheck_interval: None,
            ipv4: true,
            ipv6: false,
            portmap: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("the node is not authorized{}", .0.as_ref().map(|u| format!("; visit {u}")).unwrap_or_default())]
    NeedsLogin(Option<String>),
    #[error("control refused the node: {0}")]
    Refused(String),
    #[error("the node key expired; register again with a new key and an auth key")]
    KeyExpired,
    #[error("the mesh did not come up in time")]
    Timeout,
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// A DERP connection's handle: its task ends when this is dropped.
struct DerpConn {
    tx: mpsc::Sender<Vec<u8>>,
    /// Whether it is connected right now.
    up: Arc<std::sync::atomic::AtomicBool>,
}

impl DerpConn {
    fn is_up(&self) -> bool {
        self.up.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub(super) struct Shared {
    state: Mutex<NodeCore>,
    pub(super) wake: Notify,
    /// Set by [`Node::rebind`]; the loop picks it up on its next pass.
    rebind: std::sync::atomic::AtomicBool,
    /// Tells the map stream to reconnect (after a rebind).
    control_rebind: Notify,
}

impl Shared {
    pub(super) fn lock(&self) -> MutexGuard<'_, NodeCore> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A node on the mesh; stopped when dropped.
pub struct Node {
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    addresses: Vec<IpAddr>,
}

impl Drop for Node {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Node {
    /// Register with control and come up: returns once the node has its
    /// addresses and first netmap.
    pub async fn start(config: Config) -> Result<Self, MeshError> {
        Self::start_with(config, None).await
    }

    /// Like [`start`](Self::start), keeping the tailnet-lock chain in `store`
    /// between runs. Without a store, a restarted node takes the lock's
    /// genesis from control again (docs/rfc5-tailnet-lock.md).
    pub async fn start_with_lock_store(
        config: Config,
        store: Arc<dyn super::lock::LockStore>,
    ) -> Result<Self, MeshError> {
        Self::start_with(config, Some(store)).await
    }

    async fn start_with(
        config: Config,
        store: Option<Arc<dyn super::lock::LockStore>>,
    ) -> Result<Self, MeshError> {
        tokio::time::timeout(START_TIMEOUT, Self::start_inner(config, store))
            .await
            .map_err(|_| MeshError::Timeout)?
    }

    async fn start_inner(
        config: Config,
        store: Option<Arc<dyn super::lock::LockStore>>,
    ) -> Result<Self, MeshError> {
        let node_key = config.identity.node.0.clone();
        let node_public = config.identity.node_public();
        let disco_key = PrivateKey::generate();

        let mut paths = Paths::new(disco_key, node_public);
        paths.set_udp(config.direct);
        let disco_public = paths.disco_public();

        // Register, then the netmap stream up to its first full response
        // (tailnet lock synced on each before it applies).
        let mut lock = super::lock::Lock::new(store);
        let mut link = ControlLink::new(&config, disco_public, lock.head_text());
        let mut netmap = NetMap::default();
        let mut filter_sets = BTreeMap::new();
        loop {
            match link.next().await {
                Out::Map(mut resp) => {
                    if let Some(info) = resp.tka_info.take() {
                        if let Some(client) = link.client().cloned() {
                            super::lock::sync(&client, &node_public, &info, &mut lock).await;
                        }
                        link.session.set_tka_head(lock.head_text());
                    }
                    crate::filter::apply_update(
                        &mut filter_sets,
                        resp.packet_filter.take(),
                        resp.packet_filters.take(),
                    );
                    netmap.apply(*resp);
                    if netmap.self_node.is_some() {
                        break;
                    }
                }
                Out::Ended(e) => return Err(e),
            }
        }
        let addresses = netmap.self_addresses().to_vec();
        let home_region = mesh_core::node::pick_home(&netmap);
        tracing::info!(
            "on the mesh as {} ({}), home DERP region {:?}",
            netmap
                .self_node
                .as_ref()
                .map(|n| &*n.name)
                .unwrap_or_default(),
            addresses
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            home_region
        );

        let limits = config.limits;
        let state = NodeCore::new(
            node_key.clone(),
            paths,
            netmap,
            filter_sets,
            lock,
            Settings {
                direct: config.direct,
                ipv4: limits.ipv4,
                tcp_buffer: limits.tcp_buffer,
                listen_buffer: limits.listen_buffer,
                tcp_buffer_max: limits.tcp_buffer_max,
                tcp_send_buffer_max: limits.tcp_send_buffer_max,
                congestion: limits.congestion,
                handshake_queue: limits.handshake_queue,
                max_active_peers: limits.max_active_peers,
                udp_flows: limits.udp_flows,
                netcheck_interval: limits.netcheck_interval,
            },
            clock::now(),
        );
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            wake: Notify::new(),
            rebind: std::sync::atomic::AtomicBool::new(false),
            control_rebind: Notify::new(),
        });

        let wanted = config.limits.udp_port;
        let udp = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, wanted)).await {
            Ok(socket) => socket,
            // Taken: any port will do.
            Err(_) if wanted != 0 => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?,
            Err(e) => return Err(e.into()),
        };
        let udp = Arc::new(udp);
        // Known from the start (the loop keeps it current).
        let port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
        shared.lock().set_udp_ports(port, None);
        size_buffers(&udp, config.limits.udp_buffer);
        let udp6 = if config.limits.ipv6 {
            // The same port, where it is free: one to remember.
            let port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
            bind_udp6(port, config.limits.udp_buffer)
        } else {
            None
        };
        let (derp_tx, derp_rx) = mpsc::channel::<Received>(config.limits.derp_queue);
        let (map_tx, map_rx) = mpsc::channel::<MapResponse>(16);
        let (endpoints_tx, endpoints_rx) =
            watch::channel::<Vec<(SocketAddr, EndpointType)>>(Vec::new());
        let (port_tx, port_rx) = watch::channel::<u16>(udp.local_addr()?.port());
        let (home_tx, home_rx) = watch::channel::<HomeReport>((home_region, BTreeMap::new()));

        let tasks = vec![
            // Control: the map stream into the loop, our endpoints and home out.
            tokio::spawn(control_loop(
                shared.clone(),
                link,
                node_public,
                map_tx,
                home_rx,
                endpoints_rx,
            )),
            tokio::spawn(run_loop(
                shared.clone(),
                udp,
                udp6,
                node_key,
                config.direct,
                config.limits,
                derp_tx,
                derp_rx,
                map_rx,
                endpoints_tx,
                port_tx,
                home_tx,
            )),
        ];
        #[cfg(feature = "portmap")]
        let tasks = {
            let mut tasks = tasks;
            if config.limits.portmap && config.direct && config.limits.ipv4 {
                tasks.push(tokio::spawn(super::portmap::run(shared.clone(), port_rx)));
            }
            tasks
        };
        #[cfg(not(feature = "portmap"))]
        drop(port_rx);

        Ok(Self {
            shared,
            tasks,
            addresses,
        })
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Tailnet lock as this node sees it (docs/rfc5-tailnet-lock.md).
    pub fn lock_status(&self) -> super::lock::LockStatus {
        self.shared.lock().lock().status()
    }

    /// The DERP region this node is homed to (where peers reach it).
    pub fn home_region(&self) -> Option<i32> {
        self.shared.lock().home_region()
    }

    /// Inbound packets the tailnet's packet filter has dropped so far.
    pub fn filtered_packets(&self) -> u64 {
        self.shared.lock().filtered_packets()
    }

    /// Outbound packets dropped so far because a DERP connection could not
    /// take them fast enough ([`Limits::derp_queue`]).
    pub fn derp_dropped(&self) -> u64 {
        self.shared.lock().derp_dropped()
    }

    /// A snapshot of the netmap.
    pub fn netmap(&self) -> NetMap {
        self.shared.lock().netmap().clone()
    }

    /// The network changed (a new Wi-Fi, an address change, a link that came
    /// back): take a fresh UDP socket, forget direct paths, reconnect DERP
    /// and control, and rediscover endpoints now instead of on timeouts.
    /// WireGuard sessions are kept, so open connections carry on.
    pub fn rebind(&self) {
        self.shared
            .rebind
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.shared.wake.notify_one();
        self.shared.control_rebind.notify_one();
    }

    /// Never drop this peer's tunnel state for [`Limits::max_active_peers`]
    /// (e.g. the server a device reports to).
    pub fn set_priority_peer(&self, host: &str) -> io::Result<()> {
        let ip = self.resolve(host)?;
        self.shared.lock().set_priority(Some(ip));
        Ok(())
    }

    /// Accept TCP connections from peers on `port` of this node's tailnet
    /// addresses.
    pub fn listen(&self, port: u16) -> io::Result<TcpListener> {
        let handle = self
            .shared
            .lock()
            .netstack_mut()
            .listen(port)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
        self.shared.wake.notify_one();
        Ok(TcpListener {
            shared: self.shared.clone(),
            port,
            handle,
        })
    }

    /// The local port of the node's UDP socket (WireGuard, disco, STUN).
    pub fn udp_port(&self) -> u16 {
        self.shared.lock().udp_port()
    }

    /// Whether the peer `host` currently has WireGuard state.
    pub fn is_active(&self, host: &str) -> bool {
        let Ok(ip) = self.resolve(host) else {
            return false;
        };
        let state = self.shared.lock();
        state
            .netmap()
            .peer_by_ip(ip)
            .is_some_and(|p| state.tunnel().has_peer(&p.key))
    }

    /// How many peers currently have WireGuard state.
    pub fn active_peers(&self) -> usize {
        self.shared.lock().tunnel().len()
    }

    /// The trusted direct path to the peer at `ip`, if one is up.
    pub fn direct_path(&self, ip: IpAddr) -> Option<SocketAddr> {
        let state = self.shared.lock();
        let key = state.netmap().peer_by_ip(ip)?.key;
        state.paths().direct(&key, clock::now())
    }

    /// A peer's tailnet address: an IP literal, or a name in the netmap
    /// (bare hostname or FQDN).
    pub fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse() {
            return Ok(ip);
        }
        let state = self.shared.lock();
        let peer = state.netmap().peer_by_name(host).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no peer named {host} on the mesh"),
            )
        })?;
        peer.primary_address().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"))
        })
    }

    /// Bind a UDP socket on the mesh (`port` 0 picks one). It sends only
    /// to peers, and receives what peers send to it.
    #[cfg(feature = "udp")]
    pub fn bind_udp(&self, port: u16) -> io::Result<super::udp::UdpSocket> {
        self.udp_binder()?.bind(port)
    }

    /// What binds UDP sockets on this node, for use apart from it.
    #[cfg(feature = "udp")]
    pub fn udp_binder(&self) -> io::Result<super::udp::UdpBinder> {
        let ip = self
            .addresses
            .iter()
            .find(|a| a.is_ipv4())
            .or(self.addresses.first())
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no mesh address"))?;
        Ok(super::udp::UdpBinder {
            shared: self.shared.clone(),
            ip,
        })
    }

    /// Open a TCP connection to `host:port` on the mesh.
    pub async fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let ip = self.resolve(host)?;
        let remote = SocketAddr::new(ip, port);
        let handle = {
            let mut state = self.shared.lock();
            if state.netmap().peer_by_ip(ip).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{ip} is not a peer on the mesh"),
                ));
            }
            state
                .netstack_mut()
                .connect(remote)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };
        self.shared.wake.notify_one();
        let mut stream = TcpStream {
            shared: self.shared.clone(),
            handle,
            established: false,
        };
        let connected =
            tokio::time::timeout(CONNECT_TIMEOUT, poll_fn(|cx| stream.poll_connected(cx))).await;
        match connected {
            Ok(Ok(())) => {
                stream.established = true;
                Ok(stream)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connecting to {remote} timed out"),
            )),
        }
    }
}

/// Control, after the start: map responses into the node (tailnet lock
/// synced first, on a copy the node keeps filtering without meanwhile),
/// our endpoints, home and lock head out, rebinds in. The policy is the
/// session's ([`ControlLink`]).
async fn control_loop(
    shared: Arc<Shared>,
    mut link: ControlLink,
    node_public: crate::keys::NodePublic,
    map_tx: mpsc::Sender<MapResponse>,
    mut home: watch::Receiver<HomeReport>,
    mut endpoints: watch::Receiver<Vec<(SocketAddr, EndpointType)>>,
) {
    link.session.set_home(home.borrow_and_update().clone());
    link.session
        .set_endpoints(endpoints.borrow_and_update().clone());
    loop {
        tokio::select! {
            out = link.next() => match out {
                Out::Map(mut resp) => {
                    // Tailnet lock first, so the change is judged by the
                    // chain it came with.
                    let info = resp.tka_info.take();
                    let stale = info
                        .as_ref()
                        .is_some_and(|i| shared.lock().lock().needs_sync(i));
                    if let (Some(info), Some(client)) = (info.filter(|_| stale), link.client().cloned()) {
                        let mut lock = shared.lock().lock().clone();
                        super::lock::sync(&client, &node_public, &info, &mut lock).await;
                        let head = lock.head_text();
                        shared.lock().set_lock(lock);
                        shared.wake.notify_one();
                        link.session.set_tka_head(head);
                    }
                    // The loop owns the netmap; hand it the change.
                    if map_tx.send(*resp).await.is_err() {
                        return;
                    }
                }
                // Only before the first registration, which the start did.
                Out::Ended(e) => {
                    tracing::warn!("control: {e}");
                    return;
                }
            },
            changed = endpoints.changed() => {
                if changed.is_err() {
                    return;
                }
                link.session.set_endpoints(endpoints.borrow_and_update().clone());
            }
            changed = home.changed() => {
                if changed.is_err() {
                    return;
                }
                link.session.set_home(home.borrow_and_update().clone());
            }
            _ = shared.control_rebind.notified() => link.session.rebind(clock::now()),
        }
    }
}

/// The node's I/O: the UDP sockets, DERP and the map stream into the core,
/// what it sends out, the DERP connections it asks for. The policy (when
/// to probe, re-home, report, hold back) is [`NodeCore`]'s.
#[allow(clippy::too_many_arguments)]
async fn run_loop(
    shared: Arc<Shared>,
    mut udp: Arc<UdpSocket>,
    mut udp6: Option<Arc<UdpSocket>>,
    node_key: PrivateKey,
    direct: bool,
    limits: Limits,
    derp_tx: mpsc::Sender<Received>,
    mut derp_rx: mpsc::Receiver<Received>,
    mut map_rx: mpsc::Receiver<MapResponse>,
    endpoints_tx: watch::Sender<Vec<(SocketAddr, EndpointType)>>,
    port_tx: watch::Sender<u16>,
    home_tx: watch::Sender<HomeReport>,
) {
    let mut local_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
    // Datagrams are at most a WireGuard packet at the tunnel MTU (plus
    // headers) or a small disco/STUN message.
    let mut buf = vec![0u8; 2048];
    let mut buf6 = vec![0u8; if udp6.is_some() { 2048 } else { 0 }];
    let mut local_port6 = udp6
        .as_ref()
        .and_then(|u| u.local_addr().ok())
        .map(|a| a.port());
    shared.lock().set_udp_ports(local_port, local_port6);
    // DERP connections, by region; aborted with this loop.
    let mut derp: HashMap<i32, DerpConn> = HashMap::new();
    let mut derp_tasks = Tasks::default();
    // The DERP connection whose full queue holds the sockets back: the loop
    // waits for it to drain before it lets them send again.
    let mut backlog: Option<mpsc::Sender<Vec<u8>>> = None;
    // What the core asks for, under the lock already held.
    let mut act = |state: &mut NodeCore, derp: &mut HashMap<i32, DerpConn>| {
        while let Some(event) = state.poll_event() {
            match event {
                Event::ConnectDerp { region, info, home } => {
                    // Replacing a connection drops its sender, which ends its task.
                    let (tx, rx) = mpsc::channel(limits.derp_queue.max(1));
                    let sending = derp_conn::Sending {
                        burst: limits.derp_burst,
                        up: Arc::default(),
                    };
                    derp.insert(
                        region,
                        DerpConn {
                            tx,
                            up: sending.up.clone(),
                        },
                    );
                    derp_tasks.0.retain(|t| !t.is_finished());
                    derp_tasks.0.push(tokio::spawn(derp_conn::run(
                        info,
                        node_key.clone(),
                        home,
                        derp_tx.clone(),
                        rx,
                        sending,
                    )));
                }
                Event::DropDerp { region } => {
                    derp.remove(&region);
                }
                Event::Endpoints(endpoints) => {
                    let _ = endpoints_tx.send(endpoints);
                }
                Event::Home(report) => {
                    let _ = home_tx.send(report);
                }
            }
        }
    };

    loop {
        let now = clock::now();
        let deadline = {
            let mut state = shared.lock();
            // The connections asked for (the home region's, at the start).
            act(&mut state, &mut derp);
            state.poll_timeout(now, backlog.is_some())
        };

        let mut transmits = Vec::new();
        tokio::select! {
            recv = udp.recv_from(&mut buf) => {
                if let Ok((n, src)) = recv {
                    let mut state = shared.lock();
                    transmits.extend(state.handle_datagram(clock::now(), src, &buf[..n]));
                    // And what else has arrived: one pass of the stack for
                    // all of it, and the kernel's buffer emptied sooner.
                    for _ in 1..RECV_BATCH {
                        let Ok((n, src)) = udp.try_recv_from(&mut buf) else {
                            break;
                        };
                        transmits.extend(state.handle_datagram(clock::now(), src, &buf[..n]));
                    }
                }
            }
            recv = async {
                match &udp6 {
                    Some(u) => u.recv_from(&mut buf6).await,
                    None => std::future::pending().await,
                }
            } => {
                if let Ok((n, src)) = recv {
                    let mut state = shared.lock();
                    transmits.extend(state.handle_datagram(clock::now(), src, &buf6[..n]));
                    if let Some(u) = &udp6 {
                        for _ in 1..RECV_BATCH {
                            let Ok((n, src)) = u.try_recv_from(&mut buf6) else {
                                break;
                            };
                            transmits.extend(state.handle_datagram(clock::now(), src, &buf6[..n]));
                        }
                    }
                }
            }
            Some(first) = derp_rx.recv() => {
                let mut state = shared.lock();
                let (mut next, mut taken) = (Some(first), 0);
                while let Some(Received { region, event }) = next.take() {
                    if let derp::Event::Packet { from, data } = event {
                        transmits.extend(state.handle_derp(clock::now(), region, from, &data));
                    }
                    taken += 1;
                    if taken < RECV_BATCH {
                        next = derp_rx.try_recv().ok();
                    }
                }
            }
            Some(resp) = map_rx.recv() => {
                shared.lock().apply_map(resp);
            }
            _ = shared.wake.notified() => {}
            // The full DERP queue is half empty again: let the sockets send.
            // Or look again shortly, should its connection have dropped.
            _ = async {
                match &backlog {
                    Some(tx) => {
                        let room = tx.reserve_many((tx.max_capacity() / 2).max(1));
                        let _ = tokio::time::timeout(BACKLOG_CHECK, room).await;
                    }
                    None => std::future::pending().await,
                }
            } => {}
            _ = tokio::time::sleep_until(clock::to_std(deadline).into()) => {}
        }

        if shared
            .rebind
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
                Ok(socket) => {
                    size_buffers(&socket, limits.udp_buffer);
                    udp = Arc::new(socket);
                    local_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
                    let _ = port_tx.send(local_port);
                }
                Err(e) => tracing::warn!("rebind: no new UDP socket: {e}"),
            }
            if udp6.is_some() {
                udp6 = bind_udp6(0, limits.udp_buffer);
                local_port6 = udp6
                    .as_ref()
                    .and_then(|u| u.local_addr().ok())
                    .map(|a| a.port());
            }
            shared.lock().rebind(clock::now(), local_port, local_port6);
            tracing::info!("rebound: UDP port {local_port}");
        }

        // Pump the stack and timers, then send with the lock released.
        let now = clock::now();
        let mut udp_sends = Vec::new();
        {
            let mut state = shared.lock();
            // A connection whose task ended is made again when next needed.
            derp.retain(|region, conn| {
                let open = !conn.tx.is_closed();
                if !open {
                    state.derp_closed(*region);
                }
                open
            });
            // What the fullest queue of a connected DERP region still takes
            // (one still connecting keeps what fits and drops the rest).
            let fullest = derp
                .values()
                .filter(|conn| conn.is_up())
                .map(|conn| &conn.tx)
                .min_by_key(|tx| tx.capacity())
                .cloned();
            let room = fullest.as_ref().map_or(usize::MAX, |tx| tx.capacity());
            let pumped = state.pump(now, room);
            backlog = if pumped.held_back { fullest } else { None };
            transmits.extend(pumped.transmits);
            if state.stun_due(now) {
                let local = (direct && limits.ipv4)
                    .then(|| local_endpoint(local_port))
                    .flatten();
                let local6 = local_port6.filter(|_| direct).and_then(local_endpoint6);
                udp_sends = state.stun(now, local, local6);
            }
            // Connect the regions the transmits go to before sending to them.
            state.link_derp_for(&transmits);
            act(&mut state, &mut derp);
            for t in transmits {
                match t.via {
                    Via::Udp(addr) => udp_sends.push((addr, t.data)),
                    Via::Derp { region, peer } => {
                        let full = derp.get(&region).is_some_and(|conn| {
                            matches!(
                                conn.tx.try_send(derp::send_packet(&peer, &t.data)),
                                Err(mpsc::error::TrySendError::Full(_))
                            )
                        });
                        if full {
                            state.count_derp_dropped();
                        }
                    }
                }
            }
        }
        for (addr, data) in udp_sends {
            let addr = canonical(addr);
            match (&udp6, addr.is_ipv6()) {
                (_, false) if limits.ipv4 => {
                    let _ = udp.send_to(&data, addr).await;
                }
                (Some(u), true) => {
                    let _ = u.send_to(&data, addr).await;
                }
                // A family this node does not use.
                _ => {}
            }
        }
        // A STUN answer may have arrived: report it on the next pass.
        shared.lock().after_pass(clock::now());
    }
}

/// How long the sockets wait on a full DERP queue before looking again.
const BACKLOG_CHECK: Duration = Duration::from_millis(100);

/// Datagrams taken from a socket (or from DERP) before the stack runs.
const RECV_BATCH: usize = 64;

/// Tasks aborted when dropped.
#[derive(Default)]
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Ask for `bytes` of kernel buffer each way (0: leave the default). The
/// system grants what it allows; less is not an error.
fn size_buffers(socket: &UdpSocket, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let socket = socket2::SockRef::from(socket);
    let _ = socket.set_recv_buffer_size(bytes);
    let _ = socket.set_send_buffer_size(bytes);
    tracing::debug!(
        "UDP buffers: {:?} in, {:?} out",
        socket.recv_buffer_size(),
        socket.send_buffer_size()
    );
}

/// A UDP socket on `[::]`, IPv6 only (so it does not take the IPv4 port
/// space too). `None` where IPv6 is unavailable.
fn bind_udp6(port: u16, buffer: usize) -> Option<Arc<UdpSocket>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let bind = |port: u16| -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        UdpSocket::from_std(socket.into())
    };
    // `port` if it is free, or any.
    match bind(port).or_else(|_| bind(0)) {
        Ok(socket) => {
            size_buffers(&socket, buffer);
            tracing::debug!("IPv6 UDP socket on {:?}", socket.local_addr());
            Some(Arc::new(socket))
        }
        Err(e) => {
            tracing::debug!("no IPv6 UDP socket ({e}); running over IPv4");
            None
        }
    }
}

/// This host's global IPv6 address on its default route, with our port.
/// Link-local, unique-local (which includes tailnet addresses) and loopback
/// addresses are not reachable from elsewhere, so none is reported.
fn local_endpoint6(port: u16) -> Option<SocketAddr> {
    let probe = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect(("2001:db8::1", 9)).ok()?;
    let IpAddr::V6(ip) = probe.local_addr().ok()?.ip() else {
        return None;
    };
    let first = ip.segments()[0];
    let global = !ip.is_loopback()
        && !ip.is_unspecified()
        && (first & 0xfe00) != 0xfc00 // unique local
        && (first & 0xffc0) != 0xfe80; // link local
    global.then(|| SocketAddr::new(IpAddr::V6(ip), port))
}

/// This host's address on its default route, with our UDP port.
fn local_endpoint(port: u16) -> Option<SocketAddr> {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // Connecting a UDP socket sends nothing; it only picks a route.
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let ip = probe.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then(|| SocketAddr::new(ip, port))
}

/// A TCP connection over the mesh.
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
    established: bool,
}

/// Accepts TCP connections from peers on one port of this node.
///
/// Connections are accepted one at a time (a new listening socket is armed
/// after each), so a burst of simultaneous connects may see resets. Which
/// peers may connect is not filtered beyond the tunnel's own check that a
/// packet's source belongs to the peer that sent it.
pub struct TcpListener {
    shared: Arc<Shared>,
    port: u16,
    handle: SocketHandle,
}

impl TcpListener {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The next connection, and the peer address it came from.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let mut state = self.shared.lock();
        let socket = state.netstack_mut().socket(self.handle);
        match socket.state() {
            TcpState::Established | TcpState::CloseWait => {
                let remote = socket
                    .remote_endpoint()
                    .map(|ep| SocketAddr::new(IpAddr::from(ep.addr), ep.port))
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                let fresh = state
                    .netstack_mut()
                    .listen(self.port)
                    .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
                let accepted = std::mem::replace(&mut self.handle, fresh);
                drop(state);
                self.shared.wake.notify_one();
                Poll::Ready(Ok((
                    TcpStream {
                        shared: self.shared.clone(),
                        handle: accepted,
                        established: true,
                    },
                    remote,
                )))
            }
            TcpState::Listen | TcpState::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            _ => {
                // A half-open attempt that failed: listen again.
                socket.abort();
                let fresh = state
                    .netstack_mut()
                    .listen(self.port)
                    .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
                let stale = std::mem::replace(&mut self.handle, fresh);
                state.close_socket(stale);
                drop(state);
                self.shared.wake.notify_one();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.netstack_mut().socket(self.handle).abort();
        state.close_socket(self.handle);
        drop(state);
        self.shared.wake.notify_one();
    }
}

impl TcpStream {
    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        let socket = state.netstack_mut().socket(self.handle);
        match socket.state() {
            TcpState::Established => Poll::Ready(Ok(())),
            TcpState::Closed | TcpState::TimeWait | TcpState::CloseWait | TcpState::LastAck => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the peer refused the connection",
                )))
            }
            _ => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        let socket = state.netstack_mut().socket(self.handle);
        if socket.can_recv() {
            let n = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()))?;
            buf.advance(n);
            drop(state);
            // Receive-window space freed: let the loop tell the peer.
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(())); // EOF
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.shared.lock();
        let socket = state.netstack_mut().socket(self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            let n = socket
                .send_slice(data)
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
            drop(state);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared
            .lock()
            .netstack_mut()
            .socket(self.handle)
            .close();
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let socket = state.netstack_mut().socket(self.handle);
        if self.established {
            socket.close();
        } else {
            socket.abort();
        }
        state.close_socket(self.handle);
        drop(state);
        self.shared.wake.notify_one();
    }
}
