//! A node with its state directory: what meshd, fakts and the Python
//! bindings run.
//!
//! State in the directory:
//! - `identity.json` holds the machine and node keys, private to this user.
//! - `control-url` is written once the node is on the mesh, so it restarts
//!   without one.
//! - `mesh.lock` allows one node per directory.
//! - `tka.json` holds the verified tailnet-lock chain, if the tailnet is locked.
//!
//! A node is joined once with an auth key and re-used on every later start
//! without one.
//!
//! On top of the node a session serves the local HTTP proxy into the mesh
//! and, with the `relay` feature, a TURN relay and TCP forwards.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::node::{Config, Limits, MeshError, Node, TcpStream};
use super::proxy::{self, Dial};
use crate::keys::{NodeIdentity, PrivateKey, StoredKey};

const IDENTITY: &str = "identity.json";
const CONTROL_URL: &str = "control-url";
const LOCK: &str = "mesh.lock";
const TKA: &str = "tka.json";
/// The UDP port of the last run, to come back on (`Limits::udp_port`).
const UDP_PORT: &str = "udp-port";
/// How long reaching a peer through the proxy may take; an offline peer
/// never answers.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// How to start a session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub statedir: PathBuf,
    pub hostname: String,
    /// The coordination server; remembered, so later starts may omit it.
    pub control_url: Option<String>,
    /// Needed to join; a node already joined in `statedir` ignores it.
    pub auth_key: Option<String>,
    /// How long joining and connecting may take.
    pub timeout: Duration,
    pub ephemeral: bool,
    pub limits: Limits,
}

impl SessionOptions {
    pub fn new(statedir: impl Into<PathBuf>, hostname: impl Into<String>) -> Self {
        Self {
            statedir: statedir.into(),
            hostname: hostname.into(),
            control_url: None,
            auth_key: None,
            timeout: Duration::from_secs(90),
            ephemeral: false,
            limits: Limits::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("this node is not on the mesh and no auth key was given")]
    NeedsLogin,
    #[error("another mesh node is already running in {}", .0.display())]
    Locked(PathBuf),
    #[error("no coordination url is known for the mesh (none given, none saved in {})", .0.display())]
    NoControlUrl(PathBuf),
    #[error("the mesh refused this node: {0}")]
    Refused(String),
    #[error("the mesh did not connect in time")]
    Timeout,
    #[error(
        "the tailnet is locked and this node's key is not signed; sign it with a \
         trusted key (`tailscale lock sign {0}`) and start again"
    )]
    LockedOut(String),
    #[error("the tailnet is locked, but its lock could not be verified: {0}")]
    LockUnverified(String),
    #[error("could not join the mesh: {0}")]
    Join(MeshError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl SessionError {
    /// The code meshd reports this as (`{"event":"error","code":…}`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::NeedsLogin => "needs_login",
            Self::Locked(_) => "locked",
            Self::NoControlUrl(_) => "usage",
            Self::Refused(_) => "login",
            Self::Timeout => "timeout",
            Self::LockedOut(_) => "locked_out",
            Self::LockUnverified(_) => "lock_unverified",
            Self::Join(_) => "start",
            Self::Io(_) => "statedir",
        }
    }
}

/// A running node with its state; stopped when dropped.
pub struct Session {
    node: Arc<Node>,
    statedir: PathBuf,
    proxy: Option<(String, JoinHandle<()>)>,
    #[cfg(feature = "relay")]
    relay: Option<super::relay::TurnRelay>,
    #[cfg(feature = "relay")]
    forwards: Vec<((String, u16), super::relay::Forward)>,
    _lock: std::fs::File,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("statedir", &self.statedir)
            .field("proxy", &self.proxy_url())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether a node was already joined in `statedir`. The identity exists
    /// from the first attempt on; the url only once the node got on.
    pub fn has_state(statedir: &Path) -> bool {
        statedir.join(IDENTITY).is_file() && statedir.join(CONTROL_URL).is_file()
    }

    /// Start the node in the state directory and wait until it is on the mesh.
    pub async fn start(options: SessionOptions) -> Result<Self, SessionError> {
        let statedir = options.statedir;
        prepare_statedir(&statedir).await?;
        let lock = lock(&statedir)?;

        let control_path = statedir.join(CONTROL_URL);
        let control_url = match options.control_url {
            Some(url) => url,
            None => tokio::fs::read_to_string(&control_path)
                .await
                .map(|url| url.trim().to_owned())
                .map_err(|_| SessionError::NoControlUrl(statedir.clone()))?,
        };
        if options.auth_key.is_none() && !Self::has_state(&statedir) {
            return Err(SessionError::NeedsLogin);
        }
        let identity = load_identity(&statedir.join(IDENTITY)).await?;
        if options.auth_key.is_some() {
            tracing::info!("joining the mesh as {}", options.hostname);
        }

        let mut limits = options.limits;
        if limits.udp_port == 0 {
            limits.udp_port = tokio::fs::read_to_string(statedir.join(UDP_PORT))
                .await
                .ok()
                .and_then(|port| port.trim().parse().ok())
                .unwrap_or(0);
        }
        let config = Config {
            control_url: control_url.clone(),
            identity,
            auth_key: options.auth_key,
            hostname: options.hostname.clone(),
            ephemeral: options.ephemeral,
            tags: Vec::new(),
            direct: true,
            limits,
        };
        let store = Arc::new(super::lock::FileLockStore(statedir.join(TKA)));
        let node_key = config.identity.node_public().text();
        let started = Node::start_with_lock_store(config, store);
        let node = match tokio::time::timeout(options.timeout, started).await {
            Ok(Ok(node)) => node,
            Ok(Err(MeshError::NeedsLogin(_))) => return Err(SessionError::NeedsLogin),
            Ok(Err(MeshError::KeyExpired)) => {
                // Keep the machine, replace the dead node key: the next
                // authorization (with an auth key) registers the new one.
                rotate_node_key(&statedir.join(IDENTITY)).await?;
                return Err(SessionError::NeedsLogin);
            }
            Ok(Err(MeshError::Refused(reason))) => return Err(SessionError::Refused(reason)),
            Ok(Err(MeshError::Timeout)) | Err(_) => return Err(SessionError::Timeout),
            Ok(Err(e)) => return Err(SessionError::Join(e)),
        };
        tokio::fs::write(&control_path, &control_url).await?;
        // Best effort: without it the next run takes any port.
        let _ = tokio::fs::write(statedir.join(UDP_PORT), node.udp_port().to_string()).await;
        match node.lock_status() {
            super::lock::LockStatus::Locked {
                locked_out: true, ..
            } => return Err(SessionError::LockedOut(node_key)),
            super::lock::LockStatus::Unverified(reason) => {
                return Err(SessionError::LockUnverified(reason))
            }
            _ => {}
        }
        tracing::info!(
            "on the mesh as {} ({})",
            options.hostname,
            node.addresses()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(Self {
            node: Arc::new(node),
            statedir,
            proxy: None,
            #[cfg(feature = "relay")]
            relay: None,
            #[cfg(feature = "relay")]
            forwards: Vec::new(),
            _lock: lock,
        })
    }

    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn statedir(&self) -> &Path {
        &self.statedir
    }

    /// Serve the local HTTP proxy into the mesh on `listen` (e.g.
    /// `127.0.0.1:0`), once; returns its url.
    pub async fn serve_proxy(&mut self, listen: &str) -> io::Result<String> {
        if let Some((url, _)) = &self.proxy {
            return Ok(url.clone());
        }
        let listener = TcpListener::bind(listen).await?;
        let (url, task) = proxy::serve_on(Tailnet(self.node.clone()), listener)?;
        self.proxy = Some((url.clone(), task));
        Ok(url)
    }

    /// The proxy's url, once it is served.
    pub fn proxy_url(&self) -> Option<&str> {
        self.proxy.as_ref().map(|(url, _)| url.as_str())
    }

    /// Start the TURN relay (once) and describe it as an ICE server.
    #[cfg(feature = "relay")]
    pub async fn turn(&mut self) -> io::Result<super::relay::TurnInfo> {
        if self.relay.is_none() {
            let relay = super::relay::TurnRelay::start(self.node.udp_binder()?).await?;
            self.relay = Some(relay);
        }
        Ok(self.relay.as_ref().expect("started").info().clone())
    }

    /// A local port forwarding to `host:port` on the mesh; one per target.
    #[cfg(feature = "relay")]
    pub async fn forward(&mut self, host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
        let key = (host.to_owned(), port);
        if let Some((_, forward)) = self.forwards.iter().find(|(k, _)| *k == key) {
            return Ok(forward.local_addr());
        }
        let forward = self.node.forward_tcp(host, port).await?;
        let addr = forward.local_addr();
        self.forwards.push((key, forward));
        Ok(addr)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Closes the proxied connections; the node stops with the last handle.
        if let Some((_, task)) = &self.proxy {
            task.abort();
        }
    }
}

/// Create the node's state directory, private to this user.
async fn prepare_statedir(statedir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(statedir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(statedir, std::fs::Permissions::from_mode(0o700)).await;
    }
    Ok(())
}

/// The node's keys, made on first use and kept private to this user.
async fn load_identity(path: &Path) -> io::Result<NodeIdentity> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unreadable mesh identity {}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let identity = NodeIdentity::generate();
            let json = serde_json::to_vec(&identity).expect("keys serialize");
            write_private(path, &json).await?;
            Ok(identity)
        }
        Err(e) => Err(e),
    }
}

/// Replace the node key, keeping the machine key.
async fn rotate_node_key(path: &Path) -> io::Result<()> {
    let mut identity = load_identity(path).await?;
    identity.node = StoredKey(PrivateKey::generate());
    let json = serde_json::to_vec(&identity).expect("keys serialize");
    write_private(path, &json).await
}

async fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, data).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }
    tokio::fs::rename(&tmp, path).await
}

/// One node per state directory: two would fight over the same identity.
/// The OS drops the lock with the process, so a crash leaves none behind.
fn lock(statedir: &Path) -> Result<std::fs::File, SessionError> {
    let file = std::fs::File::create(statedir.join(LOCK))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(SessionError::Locked(statedir.to_owned())),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Dials peers on the tailnet by IP or by name (from the netmap).
struct Tailnet(Arc<Node>);

impl Dial for Tailnet {
    type Stream = TcpStream;

    async fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        tokio::time::timeout(DIAL_TIMEOUT, self.0.dial(host, port))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the peer did not answer"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_node_in_the_same_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _first = lock(dir.path()).unwrap();
        assert!(matches!(lock(dir.path()), Err(SessionError::Locked(_))));
    }

    #[tokio::test]
    async fn the_identity_is_made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY);
        let first = load_identity(&path).await.unwrap();
        let again = load_identity(&path).await.unwrap();
        assert_eq!(first.node_public(), again.node_public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn an_expired_node_key_is_replaced_but_the_machine_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY);
        let before = load_identity(&path).await.unwrap();
        rotate_node_key(&path).await.unwrap();
        let after = load_identity(&path).await.unwrap();
        assert_eq!(after.machine_public(), before.machine_public());
        assert_ne!(after.node_public(), before.node_public());
    }

    #[tokio::test]
    async fn without_a_key_or_state_it_needs_a_login() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = SessionOptions::new(dir.path().join("n"), "app");
        options.control_url = Some("http://127.0.0.1:1".into());
        let err = Session::start(options).await.unwrap_err();
        assert!(matches!(err, SessionError::NeedsLogin), "{err}");
        assert_eq!(err.code(), "needs_login");
    }

    #[tokio::test]
    async fn without_a_url_it_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = Session::start(SessionOptions::new(dir.path().join("n"), "app"))
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::NoControlUrl(_)), "{err}");
    }
}
