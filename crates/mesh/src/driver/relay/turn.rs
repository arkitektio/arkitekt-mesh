//! A TURN server on 127.0.0.1 whose allocations are UDP sockets on the mesh.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use tokio::sync::Notify;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::RelayAddressGenerator;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use webrtc_util::Conn;

use crate::driver::udp::{UdpBinder, UdpSocket};

const REALM: &str = "arkitekt-mesh";

/// How a WebRTC client reaches the relay: one ICE server entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TurnInfo {
    /// e.g. `["turn:127.0.0.1:41234?transport=udp"]`
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// A running TURN relay; stopped when dropped (or with [`close`](Self::close)).
pub struct TurnRelay {
    server: Option<Server>,
    info: TurnInfo,
}

impl TurnRelay {
    /// Start a TURN server on a free 127.0.0.1 UDP port, relaying over the
    /// mesh through `binder` (see [`Node::udp_binder`](crate::driver::Node::udp_binder)).
    pub async fn start(binder: UdpBinder) -> io::Result<Self> {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let username = random_hex(8);
        let credential = random_hex(16);
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: Arc::new(listener),
                relay_addr_generator: Box::new(MeshRelay(binder)),
            }],
            realm: REALM.into(),
            auth_handler: Arc::new(Credentials {
                username: username.clone(),
                key: generate_auth_key(&username, REALM, &credential),
            }),
            channel_bind_timeout: std::time::Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .map_err(io::Error::other)?;
        Ok(Self {
            server: Some(server),
            info: TurnInfo {
                urls: vec![format!("turn:127.0.0.1:{port}?transport=udp")],
                username,
                credential,
            },
        })
    }

    /// What to hand the WebRTC client as its (only) ICE server.
    pub fn info(&self) -> &TurnInfo {
        &self.info
    }

    pub async fn close(mut self) {
        if let Some(server) = self.server.take() {
            let _ = server.close().await;
        }
    }
}

impl Drop for TurnRelay {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = server.close().await;
                });
            }
        }
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// One user, one password, made up per relay.
struct Credentials {
    username: String,
    key: Vec<u8>,
}

impl AuthHandler for Credentials {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src: SocketAddr,
    ) -> Result<Vec<u8>, turn::Error> {
        if username == self.username {
            Ok(self.key.clone())
        } else {
            Err(turn::Error::ErrNoSuchUser)
        }
    }
}

/// Allocations are mesh UDP sockets: the relayed address is ours on the mesh.
struct MeshRelay(UdpBinder);

#[async_trait]
impl RelayAddressGenerator for MeshRelay {
    fn validate(&self) -> Result<(), turn::Error> {
        Ok(())
    }

    async fn allocate_conn(
        &self,
        _use_ipv4: bool,
        requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
        let socket = self
            .0
            .bind(requested_port)
            .map_err(|e| turn::Error::Other(e.to_string()))?;
        let addr = socket.local_addr();
        Ok((Arc::new(MeshConn::new(socket)), addr))
    }
}

/// A mesh UDP socket as the TURN server's packet connection.
struct MeshConn {
    socket: UdpSocket,
    closed: AtomicBool,
    close: Notify,
}

impl MeshConn {
    fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            closed: AtomicBool::new(false),
            close: Notify::new(),
        }
    }

    fn check_open(&self) -> Result<(), webrtc_util::Error> {
        if self.closed.load(Ordering::Acquire) {
            Err(webrtc_util::Error::ErrUseClosedNetworkConn)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Conn for MeshConn {
    async fn connect(&self, _addr: SocketAddr) -> Result<(), webrtc_util::Error> {
        Err(webrtc_util::Error::Other(
            "mesh relay sockets are not connected".into(),
        ))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
        Ok(self.recv_from(buf).await?.0)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), webrtc_util::Error> {
        self.check_open()?;
        // The server's relay loop ends when this errors, so closing must
        // wake a pending receive.
        let closed = self.close.notified();
        tokio::select! {
            got = self.socket.recv_from(buf) => Ok(got?),
            _ = closed => Err(webrtc_util::Error::ErrUseClosedNetworkConn),
        }
    }

    async fn send(&self, _buf: &[u8]) -> Result<usize, webrtc_util::Error> {
        Err(webrtc_util::Error::Other(
            "mesh relay sockets are not connected".into(),
        ))
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, webrtc_util::Error> {
        self.check_open()?;
        Ok(self.socket.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> {
        Ok(self.socket.local_addr())
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> Result<(), webrtc_util::Error> {
        self.closed.store(true, Ordering::Release);
        self.close.notify_waiters();
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}
