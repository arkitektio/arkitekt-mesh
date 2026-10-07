//! A local TCP port that forwards each connection to `host:port` on the mesh.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use crate::driver::Node;

/// The buffer, each way, of a connection's copy.
const COPY_BUFFER: usize = 64 * 1024;

/// A running forward; stopped (with its connections) when dropped.
pub struct Forward {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Forward {
    /// The local address to connect to, on 127.0.0.1.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    /// Listen on a free 127.0.0.1 port and forward every connection to
    /// `host:port` on the mesh. For clients that cannot use the HTTP proxy
    /// (e.g. LiveKit's signaling websocket).
    pub async fn forward_tcp(self: &Arc<Self>, host: &str, port: u16) -> io::Result<Forward> {
        // Fail now rather than on the first connection.
        let ip = self.resolve(host)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let node = Arc::downgrade(self);
        let target = ip.to_string();
        let task = tokio::spawn(async move {
            // Owned here, so stopping the forward stops its connections.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut local, _)) = accepted else { continue };
                        let Some(node) = node.upgrade() else { return };
                        let target = target.clone();
                        connections.spawn(async move {
                            match node.dial(&target, port).await {
                                Ok(mut remote) => {
                                    let copied = tokio::io::copy_bidirectional_with_sizes(
                                        &mut local,
                                        &mut remote,
                                        COPY_BUFFER,
                                        COPY_BUFFER,
                                    );
                                    let _ = copied.await;
                                }
                                Err(e) => tracing::debug!("forward to {target}:{port}: {e}"),
                            }
                        });
                    }
                    Some(_) = connections.join_next() => {}
                }
            }
        });
        Ok(Forward { addr, task })
    }
}
