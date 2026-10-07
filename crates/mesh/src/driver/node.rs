//! A running mesh node: control, DERP, a UDP socket, WireGuard and the
//! netstack, driven by one loop that owns the state.
//!
//! App sockets ([`TcpStream`]) share the state behind a mutex; they wake
//! the loop after every read and write, and smoltcp wakes them back.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use super::control::{ControlClient, ControlError};
use super::derp::{self as derp_conn, Received};
use crate::control::netmap::NetMap;
use crate::control::types::DerpRegion;
use crate::control::types::{
    EndpointType, Hostinfo, MapRequest, MapResponse, NetInfo, RegisterAuth, RegisterRequest,
    CAPABILITY_VERSION,
};
use crate::derp::{self, Event};
use crate::keys::{NodeIdentity, NodePublic, PrivateKey};
use crate::netstack::{self, Netstack};
use crate::paths::{Paths, Transmit, Via};
use crate::wg::{self, Tunnel};
use crate::{disco, stun};

const STUN_INTERVAL: Duration = Duration::from_secs(20);
/// Control and DERP servers send keepalives every minute; after this long
/// without anything, the connection is presumed dead.
pub(crate) const QUIET_LIMIT: Duration = Duration::from_secs(120);
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

pub(super) struct State {
    tunnel: Tunnel,
    paths: Paths,
    pub(super) netstack: Netstack,
    pub(super) netmap: NetMap,
    home_region: Option<i32>,
    /// DERP connections, by region.
    derp: HashMap<i32, DerpConn>,
    /// Sockets the app closed, removed once their close completes.
    closing: Vec<SocketHandle>,
    /// STUN probes in flight and each region's measured latency.
    netcheck: crate::netcheck::Netcheck,
    stun_endpoint: Option<SocketAddr>,
    /// Our IPv6 address as a STUN server saw it.
    stun_endpoint6: Option<SocketAddr>,
    /// The public address our gateway maps to our UDP port, if any.
    pub(super) portmap_endpoint: Option<SocketAddr>,
    derp_queue: usize,
    derp_burst: usize,
    /// Packets dropped because a DERP connection's queue was full.
    derp_dropped: u64,
    /// The DERP connection whose full queue holds the sockets back: the
    /// loop waits for it to drain before it lets them send again.
    backlog: Option<mpsc::Sender<Vec<u8>>>,
    max_active_peers: usize,
    /// The peer (by tailnet address) exempt from eviction.
    priority: Option<IpAddr>,
    /// Our UDP socket's port (it changes on rebind).
    udp_port: u16,
    /// The tailnet's ACLs on inbound packets, by named set as control sends
    /// them, and the firewall compiled from them.
    filter_sets: BTreeMap<String, Vec<crate::filter::FilterRule>>,
    firewall: crate::filter::Firewall,
    /// Tailnet lock: the verified authority, and which peers it hides.
    lock: super::lock::Lock,
}

/// A DERP connection's handle: its task ends when this is dropped.
struct DerpConn {
    /// The region description it was made for.
    made_for: DerpRegion,
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
    state: Mutex<State>,
    pub(super) wake: Notify,
    /// Set by [`Node::rebind`]; the loop picks it up on its next pass.
    rebind: std::sync::atomic::AtomicBool,
    /// Tells the map stream to reconnect (after a rebind).
    control_rebind: Notify,
}

impl Shared {
    pub(super) fn lock(&self) -> MutexGuard<'_, State> {
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
        let machine = config.identity.machine.0.clone();
        let node_key = config.identity.node.0.clone();
        let node_public = config.identity.node_public();
        let disco_key = PrivateKey::generate();

        let client = ControlClient::connect(&config.control_url, &machine).await?;
        register(&client, &config).await?;

        let mut paths = Paths::new(disco_key, node_public);
        paths.set_udp(config.direct);
        let disco_public = paths.disco_public();

        // The netmap stream, then its first response.
        let mut lock = super::lock::Lock::new(store);
        let mut stream = client
            .map(&map_request(
                &config,
                disco_public,
                true,
                &(None, BTreeMap::new()),
                &[],
                &lock.head_text(),
            ))
            .await?;
        let mut netmap = NetMap::default();
        let mut filter_sets = BTreeMap::new();
        loop {
            match stream.next().await? {
                Some(mut resp) => {
                    if let Some(info) = resp.tka_info.take() {
                        super::lock::sync(&client, &node_public, &info, &mut lock).await;
                    }
                    crate::filter::apply_update(
                        &mut filter_sets,
                        resp.packet_filter.take(),
                        resp.packet_filters.take(),
                    );
                    netmap.apply(resp);
                    if netmap.self_node.is_some() {
                        break;
                    }
                }
                None => return Err(ControlError::Protocol("the map stream ended".into()).into()),
            }
        }
        let addresses = netmap.self_addresses().to_vec();
        let home_region = pick_home(&netmap);
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

        let now = Instant::now();
        let limits = config.limits;
        let mut tunnel = Tunnel::new(node_key.clone());
        tunnel.set_max_queued(limits.handshake_queue);
        let mut netstack = Netstack::new(&addresses, now);
        netstack.set_tcp_buffer(limits.tcp_buffer);
        netstack.set_listen_buffer(limits.listen_buffer);
        netstack.set_congestion(limits.congestion);
        let mut state = State {
            tunnel,
            paths,
            netstack,
            netmap,
            home_region,
            derp: HashMap::new(),
            closing: Vec::new(),
            netcheck: crate::netcheck::Netcheck::new(),
            stun_endpoint: None,
            stun_endpoint6: None,
            portmap_endpoint: None,
            derp_queue: limits.derp_queue.max(1),
            derp_burst: limits.derp_burst,
            derp_dropped: 0,
            backlog: None,
            max_active_peers: limits.max_active_peers,
            priority: None,
            udp_port: 0,
            firewall: {
                let mut firewall = crate::filter::Firewall::new(limits.udp_flows);
                firewall.set_filter(crate::filter::compile(&filter_sets));
                firewall
            },
            filter_sets,
            lock,
        };
        state.apply_lock();
        state.sync_peers();
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
        shared.lock().udp_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
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
        let (head_tx, head_rx) = watch::channel::<String>(shared.lock().lock.head_text());
        let (client_tx, client_rx) = watch::channel(client);

        let tasks = vec![
            // The map stream: netmap updates into the loop.
            tokio::spawn(map_loop(
                shared.clone(),
                client_tx,
                config.clone(),
                disco_public,
                stream,
                map_tx,
                head_tx,
            )),
            // Endpoint and home updates to control.
            tokio::spawn(update_loop(
                client_rx,
                config.clone(),
                disco_public,
                home_rx,
                endpoints_rx,
                head_rx,
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
        self.shared.lock().lock.status()
    }

    /// The DERP region this node is homed to (where peers reach it).
    pub fn home_region(&self) -> Option<i32> {
        self.shared.lock().home_region
    }

    /// Inbound packets the tailnet's packet filter has dropped so far.
    pub fn filtered_packets(&self) -> u64 {
        self.shared.lock().firewall.dropped()
    }

    /// Outbound packets dropped so far because a DERP connection could not
    /// take them fast enough ([`Limits::derp_queue`]).
    pub fn derp_dropped(&self) -> u64 {
        self.shared.lock().derp_dropped
    }

    /// A snapshot of the netmap.
    pub fn netmap(&self) -> NetMap {
        self.shared.lock().netmap.clone()
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
        self.shared.lock().priority = Some(ip);
        Ok(())
    }

    /// Accept TCP connections from peers on `port` of this node's tailnet
    /// addresses.
    pub fn listen(&self, port: u16) -> io::Result<TcpListener> {
        let handle = self
            .shared
            .lock()
            .netstack
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
        self.shared.lock().udp_port
    }

    /// Whether the peer `host` currently has WireGuard state.
    pub fn is_active(&self, host: &str) -> bool {
        let Ok(ip) = self.resolve(host) else {
            return false;
        };
        let state = self.shared.lock();
        state
            .netmap
            .peer_by_ip(ip)
            .is_some_and(|p| state.tunnel.has_peer(&p.key))
    }

    /// How many peers currently have WireGuard state.
    pub fn active_peers(&self) -> usize {
        self.shared.lock().tunnel.len()
    }

    /// The trusted direct path to the peer at `ip`, if one is up.
    pub fn direct_path(&self, ip: IpAddr) -> Option<SocketAddr> {
        let state = self.shared.lock();
        let key = state.netmap.peer_by_ip(ip)?.key;
        state.paths.direct(&key, Instant::now())
    }

    /// A peer's tailnet address: an IP literal, or a name in the netmap
    /// (bare hostname or FQDN).
    pub fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse() {
            return Ok(ip);
        }
        let state = self.shared.lock();
        let peer = state.netmap.peer_by_name(host).ok_or_else(|| {
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
            if state.netmap.peer_by_ip(ip).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{ip} is not a peer on the mesh"),
                ));
            }
            state
                .netstack
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

async fn register(client: &ControlClient, config: &Config) -> Result<(), MeshError> {
    let resp = client
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: config.identity.node_public(),
            auth: config
                .auth_key
                .clone()
                .map(|auth_key| RegisterAuth { auth_key }),
            hostinfo: hostinfo(config, &(None, BTreeMap::new())),
            ephemeral: config.ephemeral,
            ..Default::default()
        })
        .await?;
    if !resp.error.is_empty() {
        return Err(MeshError::Refused(resp.error));
    }
    if resp.node_key_expired {
        return Err(MeshError::KeyExpired);
    }
    if !resp.auth_url.is_empty() {
        return Err(MeshError::NeedsLogin(Some(resp.auth_url)));
    }
    if !resp.machine_authorized {
        return Err(MeshError::NeedsLogin(None));
    }
    Ok(())
}

/// What we tell control about our home region: it, and every region's latency.
type HomeReport = (Option<i32>, BTreeMap<String, f64>);

fn hostinfo(config: &Config, home: &HomeReport) -> Hostinfo {
    Hostinfo {
        ipn_version: concat!("arkitekt-mesh/", env!("CARGO_PKG_VERSION")).into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hostname: config.hostname.clone(),
        app: "arkitekt".into(),
        request_tags: config.tags.clone(),
        net_info: home.0.map(|preferred_derp| NetInfo {
            preferred_derp,
            derp_latency: home.1.clone(),
        }),
    }
}

fn map_request(
    config: &Config,
    disco: crate::keys::DiscoPublic,
    stream: bool,
    home: &HomeReport,
    endpoints: &[(SocketAddr, EndpointType)],
    tka_head: &str,
) -> MapRequest {
    MapRequest {
        version: CAPABILITY_VERSION,
        node_key: config.identity.node_public(),
        disco_key: disco,
        stream,
        keep_alive: stream,
        omit_peers: !stream,
        hostinfo: hostinfo(config, home),
        endpoints: endpoints.iter().map(|(e, _)| *e).collect(),
        endpoint_types: endpoints.iter().map(|(_, t)| *t as u8).collect(),
        tka_head: tka_head.to_owned(),
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// The regions a node may home to: not avoided, measurable, with a DERP node.
fn home_candidates(netmap: &NetMap) -> Vec<i32> {
    netmap
        .derp_regions
        .values()
        .filter(|r| !r.avoid && !r.no_measure_no_home && r.nodes.iter().any(|n| !n.stun_only))
        .map(|r| r.region_id)
        .collect()
}

/// The home to start with, before anything is measured: the lowest region.
fn pick_home(netmap: &NetMap) -> Option<i32> {
    home_candidates(netmap).into_iter().min()
}

/// Re-pick the home region from the measured latencies; on a switch,
/// connect the new home (it announces itself as preferred), drop the old
/// one (it reconnects as a plain region when next used), and tell control.
fn rehome(
    state: &mut State,
    now: Instant,
    node_key: &PrivateKey,
    events: &mpsc::Sender<Received>,
    tasks: &mut Tasks,
    report: &watch::Sender<HomeReport>,
) {
    let candidates = home_candidates(&state.netmap);
    let latencies: BTreeMap<String, f64> = state
        .netcheck
        .latencies(now)
        .into_iter()
        .map(|(region, d)| (format!("{region}-v4"), d.as_secs_f64()))
        .collect();
    if let Some(new) = state.netcheck.choose(state.home_region, &candidates, now) {
        let old = state.home_region.replace(new);
        tracing::info!(
            "home DERP region {old:?} -> {new} ({:?})",
            state.netcheck.latency(new, now)
        );
        if let Some(old) = old {
            state.derp.remove(&old);
        }
        ensure_derp(state, new, node_key, events, tasks);
        let _ = report.send((Some(new), latencies));
    } else if report.borrow().1.is_empty() && !latencies.is_empty() {
        // The first measurement: report it once even without a switch.
        let home = state.home_region;
        let _ = report.send((home, latencies));
    }
}

/// Keep the map stream going; reconnect when it drops, and publish the
/// new connection for the update loop.
async fn map_loop(
    shared: Arc<Shared>,
    client: watch::Sender<ControlClient>,
    config: Config,
    disco: crate::keys::DiscoPublic,
    mut stream: super::control::MapStream,
    map_tx: mpsc::Sender<MapResponse>,
    head_tx: watch::Sender<String>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        loop {
            // Control sends a keepalive every minute: silence means a dead link.
            let next = tokio::select! {
                next = tokio::time::timeout(QUIET_LIMIT, stream.next()) => match next {
                    Ok(next) => next,
                    Err(_) => {
                        tracing::debug!("the map stream went quiet; reconnecting");
                        break;
                    }
                },
                _ = shared.control_rebind.notified() => {
                    tracing::debug!("rebind: reconnecting to control");
                    backoff = Duration::from_millis(100);
                    break;
                }
            };
            match next {
                Ok(Some(mut resp)) => {
                    // Tailnet lock first, so the change is judged by the
                    // chain it came with. Synced on a copy: the loop keeps
                    // filtering with the last verified lock meanwhile.
                    let info = resp.tka_info.take();
                    let stale = info
                        .as_ref()
                        .is_some_and(|i| shared.lock().lock.needs_sync(i));
                    if let Some(info) = info.filter(|_| stale) {
                        let mut lock = shared.lock().lock.clone();
                        let current = client.borrow().clone();
                        super::lock::sync(
                            &current,
                            &config.identity.node_public(),
                            &info,
                            &mut lock,
                        )
                        .await;
                        let head = lock.head_text();
                        {
                            let mut state = shared.lock();
                            state.lock = lock;
                            state.apply_lock();
                        }
                        shared.wake.notify_one();
                        head_tx.send_if_modified(|h| {
                            let changed = *h != head;
                            *h = head;
                            changed
                        });
                    }
                    // The loop owns the netmap; hand it the change.
                    if !resp.keep_alive && map_tx.send(resp).await.is_err() {
                        return;
                    }
                    backoff = Duration::from_secs(1);
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!("map stream: {e}");
                    break;
                }
            }
        }
        // Reconnect: a fresh connection, registration and stream.
        loop {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
            let attempt = async {
                let c =
                    ControlClient::connect(&config.control_url, &config.identity.machine.0).await?;
                register(&c, &config).await?;
                let head = shared.lock().lock.head_text();
                let s = c
                    .map(&map_request(
                        &config,
                        disco,
                        true,
                        &(None, BTreeMap::new()),
                        &[],
                        &head,
                    ))
                    .await?;
                Ok::<_, MeshError>((c, s))
            };
            match attempt.await {
                Ok((c, s)) => {
                    let _ = client.send(c);
                    stream = s;
                    break;
                }
                Err(e) => tracing::warn!("reconnecting to control: {e}"),
            }
        }
    }
}

/// Tell control our endpoints and home region whenever they (or the
/// control connection) change.
async fn update_loop(
    mut client: watch::Receiver<ControlClient>,
    config: Config,
    disco: crate::keys::DiscoPublic,
    mut home: watch::Receiver<HomeReport>,
    mut endpoints: watch::Receiver<Vec<(SocketAddr, EndpointType)>>,
    mut tka_head: watch::Receiver<String>,
) {
    let mut first = true;
    loop {
        if !first {
            tokio::select! {
                changed = endpoints.changed() => if changed.is_err() { return },
                changed = home.changed() => if changed.is_err() { return },
                changed = tka_head.changed() => if changed.is_err() { return },
                changed = client.changed() => if changed.is_err() { return },
            }
        }
        first = false;
        let eps = endpoints.borrow_and_update().clone();
        let report = home.borrow_and_update().clone();
        let head = tka_head.borrow_and_update().clone();
        let req = map_request(&config, disco, false, &report, &eps, &head);
        let current = client.borrow_and_update().clone();
        match current.map(&req).await {
            // The answer is not needed (the stream brings changes): drain it.
            Ok(mut s) => while let Ok(true) = s.skip().await {},
            Err(e) => tracing::debug!("endpoint update: {e}"),
        }
    }
}

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
    shared.lock().udp_port = local_port;
    // Datagrams are at most a WireGuard packet at the tunnel MTU (plus
    // headers) or a small disco/STUN message.
    let mut buf = vec![0u8; 2048];
    let mut buf6 = vec![0u8; if udp6.is_some() { 2048 } else { 0 }];
    let mut local_port6 = udp6
        .as_ref()
        .and_then(|u| u.local_addr().ok())
        .map(|a| a.port());
    let mut next_stun = Instant::now();
    // Measure every region right away, then every `netcheck_interval`.
    let mut next_netcheck = Some(Instant::now());
    let mut reported: BTreeSet<SocketAddr> = BTreeSet::new();
    // Aborted with this loop.
    let mut derp_tasks = Tasks::default();

    // Connect the home region right away, so peers can reach us.
    {
        let mut state = shared.lock();
        if let Some(home) = state.home_region {
            ensure_derp(&mut state, home, &node_key, &derp_tx, &mut derp_tasks);
        }
    }

    loop {
        let now = Instant::now();
        let (deadline, backlog) = {
            let mut state = shared.lock();
            let mut deadline = next_stun;
            let backlog = state.backlog.clone();
            for d in [
                state.tunnel.next_deadline(),
                state.paths.next_deadline(now),
                // Held back, the stack always has something to send.
                state.netstack.poll_at(now).filter(|_| backlog.is_none()),
            ]
            .into_iter()
            .flatten()
            {
                deadline = deadline.min(d);
            }
            (deadline.max(now), backlog)
        };

        let mut transmits = Vec::new();
        // A datagram from either UDP socket.
        macro_rules! datagram {
            ($data:expr, $src:expr) => {{
                let mut state = shared.lock();
                let (data, src): (&[u8], SocketAddr) = ($data, canonical($src));
                if stun::is_stun(data) {
                    if let Some((tx, addr)) = stun::parse_response(data) {
                        let now = Instant::now();
                        if state.netcheck.answered(&tx, now).is_some() {
                            let addr = canonical(addr);
                            if addr.is_ipv4() {
                                state.stun_endpoint = Some(addr);
                            } else {
                                state.stun_endpoint6 = Some(addr);
                            }
                            rehome(
                                &mut state,
                                now,
                                &node_key,
                                &derp_tx,
                                &mut derp_tasks,
                                &home_tx,
                            );
                        }
                    }
                } else if disco::looks_like_disco(data) {
                    if direct {
                        let s = &mut *state;
                        transmits.extend(s.paths.on_disco(
                            data,
                            Via::Udp(src),
                            Instant::now(),
                            &s.netmap,
                        ));
                    }
                } else if wg::is_wireguard(data) {
                    transmits.extend(state.on_wireguard(data, Instant::now()));
                }
            }};
        }
        tokio::select! {
            recv = udp.recv_from(&mut buf) => {
                if let Ok((n, src)) = recv {
                    datagram!(&buf[..n], src);
                    // And what else has arrived: one pass of the stack for
                    // all of it, and the kernel's buffer emptied sooner.
                    for _ in 1..RECV_BATCH {
                        let Ok((n, src)) = udp.try_recv_from(&mut buf) else {
                            break;
                        };
                        datagram!(&buf[..n], src);
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
                    datagram!(&buf6[..n], src);
                    if let Some(u) = &udp6 {
                        for _ in 1..RECV_BATCH {
                            let Ok((n, src)) = u.try_recv_from(&mut buf6) else {
                                break;
                            };
                            datagram!(&buf6[..n], src);
                        }
                    }
                }
            }
            Some(first) = derp_rx.recv() => {
                let mut state = shared.lock();
                let (mut next, mut taken) = (Some(first), 0);
                while let Some(Received { region, event }) = next.take() {
                    if let Event::Packet { from, data } = event {
                        let now = Instant::now();
                        if disco::looks_like_disco(&data) {
                            let s = &mut *state;
                            let via = Via::Derp { region, peer: from };
                            transmits.extend(s.paths.on_disco(&data, via, now, &s.netmap));
                        } else if wg::is_wireguard(&data) {
                            transmits.extend(state.on_wireguard(&data, now));
                        }
                    }
                    taken += 1;
                    if taken < RECV_BATCH {
                        next = derp_rx.try_recv().ok();
                    }
                }
            }
            Some(mut resp) = map_rx.recv() => {
                let mut state = shared.lock();
                let (whole, named) = (resp.packet_filter.take(), resp.packet_filters.take());
                if crate::filter::apply_update(&mut state.filter_sets, whole, named) {
                    let filter = crate::filter::compile(&state.filter_sets);
                    state.firewall.set_filter(filter);
                }
                if state.netmap.apply(resp) {
                    state.apply_lock();
                    refresh_derp(&mut state, &node_key, &derp_tx, &mut derp_tasks);
                }
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
            _ = tokio::time::sleep_until(deadline.into()) => {}
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
            let mut state = shared.lock();
            state.udp_port = local_port;
            state.paths.reset_direct();
            state.derp.clear(); // their tasks end
                                // A new network: old latencies say nothing about it.
            state.netcheck = crate::netcheck::Netcheck::new();
            state.stun_endpoint = None;
            state.stun_endpoint6 = None;
            if let Some(home) = state.home_region {
                ensure_derp(&mut state, home, &node_key, &derp_tx, &mut derp_tasks);
            }
            drop(state);
            next_stun = Instant::now();
            next_netcheck = Some(Instant::now());
            reported.clear();
            tracing::info!("rebound: UDP port {local_port}");
        }

        // Pump the stack and timers, then send with the lock released.
        let now = Instant::now();
        let mut udp_sends = Vec::new();
        {
            let mut state = shared.lock();
            transmits.extend(state.pump(now));
            if now >= next_stun {
                next_stun =
                    now + STUN_INTERVAL + Duration::from_millis(OsRng.next_u32() as u64 % 6000);
                // Every region when a netcheck is due (DERP-only nodes too:
                // the home region matters to them most), else the home's
                // STUN for our endpoint.
                let all = next_netcheck.is_some_and(|at| now >= at);
                if all {
                    next_netcheck = limits.netcheck_interval.map(|every| now + every);
                }
                if direct || all {
                    let families = (limits.ipv4, udp6.is_some());
                    udp_sends = state.stun_requests(now, all, families);
                }
                let mut eps: BTreeSet<SocketAddr> = BTreeSet::new();
                if direct && limits.ipv4 {
                    eps.extend(state.stun_endpoint);
                    eps.extend(local_endpoint(local_port));
                }
                if direct {
                    if let Some(port6) = local_port6 {
                        eps.extend(state.stun_endpoint6);
                        eps.extend(local_endpoint6(port6));
                    }
                }
                let portmapped = state.portmap_endpoint.filter(|_| direct);
                eps.extend(portmapped);
                if eps != reported {
                    tracing::debug!("our endpoints: {eps:?}");
                    reported = eps.clone();
                    let typed: Vec<(SocketAddr, EndpointType)> = eps
                        .into_iter()
                        .map(|e| {
                            let kind = if Some(e) == portmapped {
                                EndpointType::Portmapped
                            } else if e.ip().is_loopback() || is_private(e.ip()) {
                                EndpointType::Local
                            } else {
                                EndpointType::Stun
                            };
                            (e, kind)
                        })
                        .collect();
                    state
                        .paths
                        .set_endpoints(typed.iter().map(|(e, _)| *e).collect());
                    let _ = endpoints_tx.send(typed);
                }
            }
            for t in &transmits {
                if let Via::Derp { region, .. } = t.via {
                    ensure_derp(&mut state, region, &node_key, &derp_tx, &mut derp_tasks);
                }
            }
            for t in std::mem::take(&mut transmits) {
                match t.via {
                    Via::Udp(addr) => udp_sends.push((addr, t.data)),
                    Via::Derp { region, peer } => {
                        let full = state.derp.get(&region).is_some_and(|conn| {
                            matches!(
                                conn.tx.try_send(derp::send_packet(&peer, &t.data)),
                                Err(mpsc::error::TrySendError::Full(_))
                            )
                        });
                        if full {
                            state.derp_dropped += 1;
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
        let unreported = {
            let state = shared.lock();
            [
                state.stun_endpoint,
                state.stun_endpoint6,
                state.portmap_endpoint,
            ]
            .into_iter()
            .flatten()
            .any(|e| !reported.contains(&e))
        };
        if unreported {
            next_stun = next_stun.min(Instant::now() + Duration::from_millis(50));
        }
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

fn ensure_derp(
    state: &mut State,
    region: i32,
    node_key: &PrivateKey,
    events: &mpsc::Sender<Received>,
    tasks: &mut Tasks,
) {
    let Some(info) = state.netmap.derp_regions.get(&region).cloned() else {
        return;
    };
    // Keep a live connection made for this same description of the region;
    // replacing it drops the old sender, which ends the old task.
    if state
        .derp
        .get(&region)
        .is_some_and(|conn| conn.made_for == info && !conn.tx.is_closed())
    {
        return;
    }
    let (tx, rx) = mpsc::channel(state.derp_queue);
    let sending = derp_conn::Sending {
        burst: state.derp_burst,
        up: Arc::default(),
    };
    state.derp.insert(
        region,
        DerpConn {
            made_for: info.clone(),
            tx,
            up: sending.up.clone(),
        },
    );
    let home = state.home_region == Some(region);
    tasks.0.retain(|t| !t.is_finished());
    tasks.0.push(tokio::spawn(derp_conn::run(
        info,
        node_key.clone(),
        home,
        events.clone(),
        rx,
        sending,
    )));
}

/// After a netmap change: drop DERP connections whose region moved (e.g.
/// the server restarted on a new port) or went away, and reconnect the home
/// region right away. Others reconnect when next used.
fn refresh_derp(
    state: &mut State,
    node_key: &PrivateKey,
    events: &mpsc::Sender<Received>,
    tasks: &mut Tasks,
) {
    let stale: Vec<i32> = state
        .derp
        .iter()
        .filter(|(region, conn)| state.netmap.derp_regions.get(region) != Some(&conn.made_for))
        .map(|(region, _)| *region)
        .collect();
    for region in stale {
        tracing::debug!("DERP region {region} changed; reconnecting");
        state.derp.remove(&region);
    }
    if let Some(home) = state.home_region {
        ensure_derp(state, home, node_key, events, tasks);
    }
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is (disco writes
/// IPv4 addresses mapped).
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
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

impl State {
    /// Hide the peers tailnet lock does not trust, judge our own key, then
    /// bring the stack and tunnel in line (hidden peers lose their sessions).
    fn apply_lock(&mut self) {
        let lock = &mut self.lock;
        lock.hidden = self.netmap.retain_trusted(|p| lock.trusts(p));
        lock.judge_self(self.netmap.self_node.as_ref());
        let ids: Vec<i64> = self
            .netmap
            .peers()
            .iter()
            .chain(self.netmap.untrusted())
            .map(|p| p.id)
            .collect();
        lock.forget_except(ids.into_iter());
        self.sync_peers();
    }

    /// Bring the stack and the tunnel in line with the netmap. WireGuard and
    /// path state are made when a peer is first used, so only departed
    /// peers are removed here (path state prunes itself on tick).
    fn sync_peers(&mut self) {
        self.netstack.set_addresses(self.netmap.self_addresses());
        let keys: BTreeSet<NodePublic> = self.netmap.peers().iter().map(|p| p.key).collect();
        let stale: Vec<NodePublic> = self
            .tunnel
            .peers()
            .filter(|k| !keys.contains(k))
            .copied()
            .collect();
        for key in stale {
            self.tunnel.remove_peer(&key);
        }
    }

    fn on_wireguard(&mut self, data: &[u8], now: Instant) -> Vec<Transmit> {
        let netmap = &self.netmap;
        let allowed = |key: &NodePublic| netmap.peer_by_key(key).is_some();
        let out = match self.tunnel.decapsulate_allowing(data, now, allowed) {
            Ok(out) => out,
            Err(e) => {
                tracing::trace!("dropped a WireGuard message: {e}");
                return Vec::new();
            }
        };
        self.deliver(out, now)
    }

    /// Route the tunnel's datagrams and feed arrived packets to the stack.
    fn deliver(&mut self, out: wg::Output, now: Instant) -> Vec<Transmit> {
        let mut transmits = Vec::new();
        for (peer, datagram) in out.send {
            transmits.extend(self.paths.route(&peer, datagram, now, &self.netmap));
        }
        for (peer, packet) in out.packets {
            if !accept_inbound(&self.netmap, &peer, &packet) {
                tracing::trace!("dropped a packet from {peer:?} that is not its to send");
            } else if !self.firewall.inbound(&packet, now) {
                tracing::trace!(
                    "the packet filter dropped a packet from {:?}",
                    netstack::source(&packet)
                );
            } else {
                self.netstack.input(packet);
            }
        }
        transmits
    }

    /// Run the stack and the timers until they are quiet.
    fn pump(&mut self, now: Instant) -> Vec<Transmit> {
        let mut transmits = Vec::new();
        // What the fullest queue of a connected DERP region still takes
        // (one still connecting keeps what fits and drops the rest). The
        // stack does not know which way a packet will go, so this holds
        // back every socket: but sending on would only drop packets and
        // have TCP send them again.
        let fullest = self
            .derp
            .values()
            .filter(|conn| conn.is_up() && !conn.tx.is_closed())
            .map(|conn| &conn.tx)
            .min_by_key(|tx| tx.capacity())
            .cloned();
        let mut room = fullest.as_ref().map_or(usize::MAX, |tx| tx.capacity());
        self.backlog = None;
        for _ in 0..64 {
            let packets = self.netstack.poll(now, room);
            room = room.saturating_sub(packets.len());
            if room == 0 {
                self.backlog.clone_from(&fullest);
            }
            if packets.is_empty() {
                break;
            }
            for packet in packets {
                let Some(dst) = netstack::destination(&packet) else {
                    continue;
                };
                // Replies to what we send need no rule.
                self.firewall.outbound(&packet, now);
                let Some(peer) = self.netmap.peer_by_ip(dst).map(|p| p.key) else {
                    continue;
                };
                self.tunnel.add_peer(peer);
                if let Ok(out) = self.tunnel.encapsulate(peer, &packet, now) {
                    transmits.extend(self.deliver(out, now));
                }
            }
        }
        let out = self.tunnel.tick(now);
        transmits.extend(self.deliver(out, now));
        transmits.extend(self.paths.tick(now, &self.netmap));
        self.enforce_peer_cap();

        // Sockets the app dropped go once their close completes.
        let netstack = &mut self.netstack;
        self.closing.retain(|&h| {
            let done = matches!(
                netstack.socket(h).state(),
                TcpState::Closed | TcpState::TimeWait
            );
            if done {
                netstack.remove(h);
            }
            !done
        });
        transmits
    }

    /// Keep at most `max_active_peers` peers' WireGuard and path state,
    /// dropping the least recently used (never the priority peer).
    fn enforce_peer_cap(&mut self) {
        let cap = self.max_active_peers;
        if cap == 0 || self.tunnel.len() <= cap {
            return;
        }
        let protected = self
            .priority
            .and_then(|ip| self.netmap.peer_by_ip(ip))
            .map(|p| p.key);
        let excess = self.tunnel.len() - cap;
        let evict: Vec<NodePublic> = self
            .tunnel
            .least_recently_used()
            .into_iter()
            .filter(|k| Some(*k) != protected)
            .take(excess)
            .collect();
        for key in evict {
            tracing::debug!("over {cap} active peers: dropping {key:?}'s tunnel state");
            self.tunnel.remove_peer(&key);
            self.paths.forget(&key);
        }
    }

    /// STUN requests: to every region (`all`, a netcheck), or to the home
    /// region only (for our endpoint).
    fn stun_requests(
        &mut self,
        now: Instant,
        all: bool,
        (ipv4, ipv6): (bool, bool),
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let home = self.home_region;
        crate::netcheck::targets(&self.netmap.derp_regions)
            .into_iter()
            .filter(|&(region, _)| all || Some(region) == home)
            .filter(|(_, addr)| if addr.is_ipv4() { ipv4 } else { ipv6 })
            .map(|(region, addr)| {
                let mut tx = [0u8; 12];
                OsRng.fill_bytes(&mut tx);
                self.netcheck.sent(tx, region, now);
                (addr, stun::request(&tx))
            })
            .collect()
    }
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
        let socket = state.netstack.socket(self.handle);
        match socket.state() {
            TcpState::Established | TcpState::CloseWait => {
                let remote = socket
                    .remote_endpoint()
                    .map(|ep| SocketAddr::new(IpAddr::from(ep.addr), ep.port))
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                let fresh = state
                    .netstack
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
                    .netstack
                    .listen(self.port)
                    .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
                let stale = std::mem::replace(&mut self.handle, fresh);
                state.closing.push(stale);
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
        state.netstack.socket(self.handle).abort();
        state.closing.push(self.handle);
        drop(state);
        self.shared.wake.notify_one();
    }
}

impl TcpStream {
    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        let socket = state.netstack.socket(self.handle);
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
        let socket = state.netstack.socket(self.handle);
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
        let socket = state.netstack.socket(self.handle);
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
        self.shared.lock().netstack.socket(self.handle).close();
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let socket = state.netstack.socket(self.handle);
        if self.established {
            socket.close();
        } else {
            socket.abort();
        }
        state.closing.push(self.handle);
        drop(state);
        self.shared.wake.notify_one();
    }
}

/// Cryptokey routing: a packet from `peer` is accepted only if its source
/// is one of `peer`'s addresses (or allowed IPs) and its destination is ours.
fn accept_inbound(netmap: &NetMap, peer: &NodePublic, packet: &[u8]) -> bool {
    let (Some(src), Some(dst)) = (netstack::source(packet), netstack::destination(packet)) else {
        return false;
    };
    netmap.self_addresses().contains(&dst) && netmap.peer_by_ip(src).is_some_and(|p| p.key == *peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::types::{MapResponse, Node as NetNode};
    use crate::keys::PublicKey;

    fn packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p
    }

    #[test]
    fn peers_may_only_send_from_their_own_addresses() {
        let a = NodePublic(PublicKey([1; 32]));
        let b = NodePublic(PublicKey([2; 32]));
        let node = |id, key, ip: &str| {
            crate::control::netmap::Peer::from(NetNode {
                id,
                key,
                addresses: vec![format!("{ip}/32")],
                ..Default::default()
            })
        };
        let mut netmap = NetMap::default();
        netmap.apply(MapResponse {
            node: Some(node(1, NodePublic::default(), "100.64.0.9")),
            peers: vec![node(2, a, "100.64.0.1"), node(3, b, "100.64.0.2")],
            ..Default::default()
        });
        let me = [100, 64, 0, 9];
        assert!(accept_inbound(&netmap, &a, &packet([100, 64, 0, 1], me)));
        // b claiming to be a is dropped.
        assert!(!accept_inbound(&netmap, &b, &packet([100, 64, 0, 1], me)));
        // Not for us, or not from the tailnet at all.
        assert!(!accept_inbound(
            &netmap,
            &a,
            &packet([100, 64, 0, 1], [100, 64, 0, 2])
        ));
        assert!(!accept_inbound(&netmap, &a, &packet([8, 8, 8, 8], me)));
        assert!(!accept_inbound(&netmap, &a, &[0x45, 0]));
    }
}
