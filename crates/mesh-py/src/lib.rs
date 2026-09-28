//! Python bindings for `arkitekt-mesh`: a [`Session`] (the node, its state
//! directory and the local HTTP proxy, plus the TURN relay and forwards) in
//! the Python process, driven by a tokio runtime of its own.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mesh::driver::{Session, SessionError, SessionOptions};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use tokio::sync::Mutex;

create_exception!(arkitekt_mesh, MeshError, PyException);
create_exception!(arkitekt_mesh, NeedsLogin, MeshError);
create_exception!(arkitekt_mesh, Locked, MeshError);
create_exception!(arkitekt_mesh, Refused, MeshError);
create_exception!(arkitekt_mesh, Timeout, MeshError);
create_exception!(arkitekt_mesh, LockedOut, MeshError);

fn to_py(e: SessionError) -> PyErr {
    let message = e.to_string();
    match e {
        SessionError::NeedsLogin => NeedsLogin::new_err(message),
        SessionError::Locked(_) => Locked::new_err(message),
        SessionError::Refused(_) => Refused::new_err(message),
        SessionError::Timeout => Timeout::new_err(message),
        SessionError::LockedOut(_) => LockedOut::new_err(message),
        _ => MeshError::new_err(message),
    }
}

fn io_err(e: std::io::Error) -> PyErr {
    MeshError::new_err(e.to_string())
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

type Shared = Arc<Mutex<Option<Session>>>;

/// A mesh node with its state directory; stop it with `close()`.
#[pyclass(frozen, module = "arkitekt_mesh")]
struct Node {
    session: Shared,
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
    #[pyo3(signature = (statedir, hostname, control_url=None, auth_key=None, timeout=90.0, ephemeral=false, listen="127.0.0.1:0".to_owned()))]
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
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut options = SessionOptions::new(statedir.clone(), hostname);
        options.control_url = control_url;
        options.auth_key = auth_key;
        options.timeout = Duration::from_secs_f64(timeout.max(0.0));
        options.ephemeral = ephemeral;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut session = Session::start(options).await.map_err(to_py)?;
            let proxy_url = session.serve_proxy(&listen).await.map_err(io_err)?;
            let addresses = session
                .node()
                .addresses()
                .iter()
                .map(ToString::to_string)
                .collect();
            Ok(Node {
                session: Arc::new(Mutex::new(Some(session))),
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

    fn close(&self) {
        stop(&self.session);
    }

    fn __repr__(&self) -> String {
        format!(
            "Node(proxy_url={:?}, addresses={:?})",
            self.proxy_url, self.addresses
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        stop(&self.session);
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Node>()?;
    m.add_class::<TurnInfo>()?;
    m.add("MeshError", py.get_type::<MeshError>())?;
    m.add("NeedsLogin", py.get_type::<NeedsLogin>())?;
    m.add("Locked", py.get_type::<Locked>())?;
    m.add("Refused", py.get_type::<Refused>())?;
    m.add("Timeout", py.get_type::<Timeout>())?;
    m.add("LockedOut", py.get_type::<LockedOut>())?;
    Ok(())
}
