//! Python bindings for `arkitekt-mesh`: a [`Session`] (the node, its state
//! directory and the local HTTP proxy, plus the TURN relay and forwards) in
//! the Python process, driven by a tokio runtime of its own.

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use mesh::driver::{
    ControlState, Node as DriverNode, PeerPath as DriverPath, Refusal, Session, SessionError,
    SessionOptions,
};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use tokio::sync::Mutex;

create_exception!(arkitekt_mesh, MeshError, PyException);
create_exception!(arkitekt_mesh, NeedsLogin, MeshError);
// A NeedsLogin whose cause is the node key's expiry (a new key is ready).
create_exception!(arkitekt_mesh, KeyExpired, NeedsLogin);
create_exception!(arkitekt_mesh, Locked, MeshError);
create_exception!(arkitekt_mesh, Refused, MeshError);
create_exception!(arkitekt_mesh, Timeout, MeshError);
create_exception!(arkitekt_mesh, LockedOut, MeshError);

fn to_py(e: SessionError) -> PyErr {
    let message = e.to_string();
    match e {
        SessionError::NeedsLogin => NeedsLogin::new_err(message),
        SessionError::KeyExpired => KeyExpired::new_err(message),
        SessionError::Locked(_) => Locked::new_err(message),
        SessionError::Refused(_) => Refused::new_err(message),
        SessionError::Timeout(_) => Timeout::new_err(message),
        SessionError::LockedOut(_) => LockedOut::new_err(message),
        _ => MeshError::new_err(message),
    }
}

fn io_err(e: std::io::Error) -> PyErr {
    MeshError::new_err(e.to_string())
}

/// An optional string as Python writes it: `None`, or the string quoted.
fn py_repr(value: &Option<String>) -> String {
    match value {
        Some(value) => format!("{value:?}"),
        None => "None".into(),
    }
}

/// One ICE server entry for a WebRTC client.
#[pyclass(frozen, get_all, module = "arkitekt_mesh")]
struct TurnInfo {
    urls: Vec<String>,
    username: String,
    credential: String,
}

#[pymethods]
impl TurnInfo {
    fn __repr__(&self) -> String {
        format!(
            "TurnInfo(urls={:?}, username={:?})",
            self.urls, self.username
        )
    }
}

/// How packets to a peer travel right now (see `Node.path`).
#[pyclass(frozen, get_all, module = "arkitekt_mesh")]
struct PeerPath {
    /// `"direct"`, `"relay"`, or `"idle"` (nothing sent to the peer lately).
    kind: &'static str,
    /// The peer's UDP address when direct; when relayed the DERP region code
    /// (e.g. `"waw"`, or the region id), or `"peer relay <address>"` for a
    /// node of the tailnet that forwards UDP for the two; else `None`.
    via: Option<String>,
}

#[pymethods]
impl PeerPath {
    fn __repr__(&self) -> String {
        format!("PeerPath(kind={:?}, via={})", self.kind, py_repr(&self.via))
    }
}

/// How the node stands with the coordination server (see `Node.control`).
#[pyclass(frozen, get_all, module = "arkitekt_mesh")]
struct ControlStatus {
    /// `"connected"`, `"reconnecting"` (it tries again by itself), or what
    /// takes a new login: `"key_expired"`, `"needs_login"`, `"refused"`.
    state: &'static str,
    /// Why, unless connected.
    reason: Option<String>,
}

#[pymethods]
impl ControlStatus {
    fn __repr__(&self) -> String {
        format!(
            "ControlStatus(state={:?}, reason={})",
            self.state,
            py_repr(&self.reason)
        )
    }
}

impl From<ControlState> for ControlStatus {
    fn from(state: ControlState) -> Self {
        let (state, reason) = match state {
            ControlState::Connected => ("connected", None),
            ControlState::Reconnecting(why) => ("reconnecting", Some(why)),
            ControlState::Refused(refusal) => {
                let why = refusal.to_string();
                let state = match refusal {
                    Refusal::KeyExpired => "key_expired",
                    Refusal::NeedsLogin(_) => "needs_login",
                    Refusal::Refused(_) => "refused",
                };
                (state, Some(why))
            }
        };
        Self { state, reason }
    }
}

/// The peer relay this node runs (see `Node.relay`).
#[pyclass(frozen, get_all, module = "arkitekt_mesh")]
struct RelayStatus {
    /// The UDP port it forwards on.
    port: u16,
    /// Where peers are told to reach it.
    addresses: Vec<String>,
    /// Pairs of peers it has endpoints for, and those both have bound to.
    sessions: usize,
    bound: usize,
    /// Datagrams and bytes forwarded for the pairs it has now.
    packets: u64,
    bytes: u64,
}

#[pymethods]
impl RelayStatus {
    fn __repr__(&self) -> String {
        format!(
            "RelayStatus(port={}, addresses={:?}, sessions={}, bound={}, packets={}, bytes={})",
            self.port, self.addresses, self.sessions, self.bound, self.packets, self.bytes
        )
    }
}

fn relay_status(relay: &mesh::driver::PeerRelay) -> RelayStatus {
    let sessions = relay.sessions();
    RelayStatus {
        port: relay.port(),
        addresses: relay.addrs().iter().map(ToString::to_string).collect(),
        sessions: sessions.len(),
        bound: sessions
            .iter()
            .filter(|s| s.bound.iter().all(Option::is_some))
            .count(),
        packets: sessions.iter().flat_map(|s| s.packets).sum(),
        bytes: sessions.iter().flat_map(|s| s.bytes).sum(),
    }
}

/// A ping's answer (see `Node.ping`).
#[pyclass(frozen, get_all, module = "arkitekt_mesh")]
struct Pinged {
    /// Seconds from the ping to its pong.
    latency: f64,
    /// The way both went, as `PeerPath.kind` and `PeerPath.via`.
    kind: &'static str,
    via: Option<String>,
}

#[pymethods]
impl Pinged {
    fn __repr__(&self) -> String {
        format!(
            "Pinged(latency={:.4}, kind={:?}, via={})",
            self.latency,
            self.kind,
            py_repr(&self.via)
        )
    }
}

/// A path as Python sees it: its kind, and through what.
fn path_parts(path: DriverPath) -> (&'static str, Option<String>) {
    match path {
        DriverPath::Idle => ("idle", None),
        DriverPath::Direct(addr) => ("direct", Some(addr.to_string())),
        // "relay" still, for those who know three kinds: `via` tells the
        // two apart.
        DriverPath::PeerRelay(addr) => ("relay", Some(format!("peer relay {addr}"))),
        DriverPath::Relay { region, code } => (
            "relay",
            Some(if code.is_empty() {
                region.to_string()
            } else {
                code
            }),
        ),
    }
}

type Shared = Arc<Mutex<Option<Session>>>;

/// A mesh node with its state directory; stop it with `close()`.
#[pyclass(frozen, module = "arkitekt_mesh")]
struct Node {
    session: Shared,
    /// For the synchronous lookups: weak, so it never keeps a closed node
    /// running (the node stops with its last strong handle).
    node: Weak<DriverNode>,
    #[pyo3(get)]
    proxy_url: String,
    #[pyo3(get)]
    addresses: Vec<String>,
    #[pyo3(get)]
    statedir: String,
}

fn closed() -> PyErr {
    MeshError::new_err("the node is closed")
}

/// Drop the session inside the runtime, so what it stops can clean up.
fn stop(session: &Shared) {
    let runtime = pyo3_async_runtimes::tokio::get_runtime();
    let _guard = runtime.enter();
    let taken = match session.try_lock() {
        Ok(mut slot) => slot.take(),
        // Busy (a turn()/forward() in flight): stop it from the runtime.
        Err(_) => {
            let session = session.clone();
            runtime.spawn(async move { session.lock().await.take() });
            None
        }
    };
    drop(taken);
}

#[pymethods]
impl Node {
    #[staticmethod]
    #[pyo3(signature = (statedir, hostname, control_url=None, auth_key=None, timeout=90.0, ephemeral=false, listen="127.0.0.1:0".to_owned(), *, tcp_buffer=None, proxy_auth=false))]
    #[allow(clippy::too_many_arguments)]
    fn start<'py>(
        py: Python<'py>,
        statedir: PathBuf,
        hostname: String,
        control_url: Option<String>,
        auth_key: Option<String>,
        timeout: f64,
        ephemeral: bool,
        listen: String,
        tcp_buffer: Option<usize>,
        proxy_auth: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut options = SessionOptions::new(statedir.clone(), hostname);
        options.control_url = control_url;
        options.auth_key = auth_key;
        options.timeout = Duration::from_secs_f64(timeout.max(0.0));
        options.ephemeral = ephemeral;
        if let Some(bytes) = tcp_buffer {
            options.limits.tcp_buffer = bytes;
        }
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut session = Session::start(options).await.map_err(to_py)?;
            let proxy_url = session
                .serve_proxy_with(&listen, proxy_auth)
                .await
                .map_err(io_err)?;
            let addresses = session
                .node()
                .addresses()
                .iter()
                .map(ToString::to_string)
                .collect();
            let node = Arc::downgrade(session.node());
            Ok(Node {
                session: Arc::new(Mutex::new(Some(session))),
                node,
                proxy_url,
                addresses,
                statedir: statedir.display().to_string(),
            })
        })
    }

    #[staticmethod]
    fn has_state(statedir: PathBuf) -> bool {
        Session::has_state(&statedir)
    }

    /// Start the TURN relay (once): its relayed traffic goes over the mesh.
    fn turn<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut slot = session.lock().await;
            let info = slot
                .as_mut()
                .ok_or_else(closed)?
                .turn()
                .await
                .map_err(io_err)?;
            Ok(TurnInfo {
                urls: info.urls,
                username: info.username,
                credential: info.credential,
            })
        })
    }

    /// A local `127.0.0.1:P` forwarding TCP to `host:port` on the mesh.
    fn forward<'py>(
        &self,
        py: Python<'py>,
        host: String,
        port: u16,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut slot = session.lock().await;
            let addr = slot
                .as_mut()
                .ok_or_else(closed)?
                .forward(&host, port)
                .await
                .map_err(io_err)?;
            Ok(addr.to_string())
        })
    }

    /// Relay UDP on `port` for the peers the mesh lets ask: a peer relay,
    /// where pairs that find no direct path to each other meet. `endpoints`
    /// (`"ip:port"`) are where peers are told to reach the port, for a relay
    /// behind a port forward. Started once; asked again, its status.
    #[pyo3(signature = (port, endpoints=None))]
    fn relay<'py>(
        &self,
        py: Python<'py>,
        port: u16,
        endpoints: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let endpoints = endpoints
            .unwrap_or_default()
            .iter()
            .map(|e| {
                e.parse::<std::net::SocketAddr>().map_err(|_| {
                    MeshError::new_err(format!("not an ip:port to reach the relay at: {e:?}"))
                })
            })
            .collect::<PyResult<Vec<_>>>()?;
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut slot = session.lock().await;
            let relay = slot
                .as_mut()
                .ok_or_else(closed)?
                .serve_peer_relay(port, endpoints)
                .await
                .map_err(io_err)?;
            Ok(relay_status(relay))
        })
    }

    /// The peer relay's status, or `None` if this node runs none.
    fn relay_status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let slot = session.lock().await;
            Ok(slot
                .as_ref()
                .ok_or_else(closed)?
                .peer_relay()
                .map(relay_status))
        })
    }

    /// How packets to the peer `host` (a mesh name or address) travel right
    /// now. A path starts out relayed and turns direct once one is found,
    /// usually seconds after the first packet.
    fn path(&self, py: Python<'_>, host: &str) -> PyResult<PeerPath> {
        // Without the GIL: the node's lock is taken here, and a tokio thread
        // holding it may be logging, which waits for the GIL (pyo3-log).
        let found = py.detach(|| {
            let node = self.node.upgrade().ok_or(())?;
            Ok::<_, ()>(node.path(host))
        });
        let found = found.map_err(|()| closed())?;
        let (kind, via) = path_parts(found.map_err(io_err)?);
        Ok(PeerPath { kind, via })
    }

    /// Ping the peer `host` (a disco ping, as `tailscale ping`): how long it
    /// took and the way it went, which is the way packets to the peer go
    /// right now.
    fn ping<'py>(&self, py: Python<'py>, host: String) -> PyResult<Bound<'py, PyAny>> {
        let node = self.node.upgrade().ok_or_else(closed)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (latency, path) = node.ping(&host).await.map_err(io_err)?;
            let (kind, via) = path_parts(path);
            Ok(Pinged {
                latency: latency.as_secs_f64(),
                kind,
                via,
            })
        })
    }

    /// How the node stands with the coordination server right now.
    fn control(&self, py: Python<'_>) -> PyResult<ControlStatus> {
        // Without the GIL, like `path`.
        let state = py.detach(|| self.node.upgrade().map(|node| node.control_state()));
        Ok(state.ok_or_else(closed)?.into())
    }

    /// The next change of `control()`: resolves with the new status.
    fn control_changed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let mut changes = self.node.upgrade().ok_or_else(closed)?.watch_control();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            changes.changed().await.map_err(|_| closed())?;
            let state = changes.borrow_and_update().clone();
            Ok(ControlStatus::from(state))
        })
    }

    /// The network changed (another Wi-Fi, back from sleep): reconnect and
    /// find paths again now, not on timeouts. Open connections carry on.
    fn rebind(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.node.upgrade().map(|node| node.rebind()))
            .ok_or_else(closed)
    }

    fn close(&self, py: Python<'_>) {
        // Without the GIL, like `path`: stopping takes the node's locks.
        py.detach(|| stop(&self.session));
    }

    fn __repr__(&self) -> String {
        // Without the proxy's credentials, if it has any.
        let proxy = match self.proxy_url.split_once('@') {
            Some((_, address)) => format!("http://{address}"),
            None => self.proxy_url.clone(),
        };
        format!("Node(proxy_url={proxy:?}, addresses={:?})", self.addresses)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Dropped by Python (the GIL held): released while stopping, as in
        // `close`. While the interpreter shuts down, stopped as it is.
        let session = &self.session;
        if Python::try_attach(|py| py.detach(|| stop(session))).is_none() {
            stop(session);
        }
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    // The node's log (DERP outages, control reconnects, rustls' alerts) into
    // Python's `logging`, under `arkitekt_mesh.*`. Levels are cached per
    // logger: configure logging before the first node starts. Trace is left
    // out (per-packet).
    let _ = pyo3_log::Logger::new(py, pyo3_log::Caching::LoggersAndLevels)?
        .set_prefix("arkitekt_mesh")
        .filter(log::LevelFilter::Debug)
        .install();
    m.add_class::<Node>()?;
    m.add_class::<TurnInfo>()?;
    m.add_class::<PeerPath>()?;
    m.add_class::<ControlStatus>()?;
    m.add_class::<Pinged>()?;
    m.add_class::<RelayStatus>()?;
    m.add("MeshError", py.get_type::<MeshError>())?;
    m.add("NeedsLogin", py.get_type::<NeedsLogin>())?;
    m.add("KeyExpired", py.get_type::<KeyExpired>())?;
    m.add("Locked", py.get_type::<Locked>())?;
    m.add("Refused", py.get_type::<Refused>())?;
    m.add("Timeout", py.get_type::<Timeout>())?;
    m.add("LockedOut", py.get_type::<LockedOut>())?;
    Ok(())
}
