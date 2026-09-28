//! UDP sockets over the mesh ([`Node::bind_udp`](super::Node::bind_udp)).
//!
//! Like [`TcpStream`](super::TcpStream), a socket shares the node's state
//! behind its mutex: sends and receives wake the loop, and smoltcp wakes the
//! socket back. Datagrams go only to peers in the netmap, and inbound ones
//! pass the same cryptokey check as everything else from the tunnel.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{RecvError, SendError};
use smoltcp::wire::IpEndpoint;

use super::node::Shared;
use crate::netstack::MAX_UDP_PAYLOAD;

/// Binds UDP sockets on a node's mesh address; cheap to clone, and usable
/// where the [`Node`](super::Node) itself is not (e.g. a TURN relay).
#[derive(Clone)]
pub struct UdpBinder {
    pub(super) shared: Arc<Shared>,
    pub(super) ip: std::net::IpAddr,
}

impl UdpBinder {
    /// Bind a socket on `port` (0 picks one).
    pub fn bind(&self, port: u16) -> io::Result<UdpSocket> {
        let (handle, port) = self
            .shared
            .lock()
            .netstack
            .bind_udp(port)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("{e:?}")))?;
        Ok(UdpSocket::new(
            self.shared.clone(),
            handle,
            SocketAddr::new(self.ip, port),
        ))
    }
}

/// A UDP socket on the mesh; closed when dropped.
pub struct UdpSocket {
    shared: Arc<Shared>,
    handle: SocketHandle,
    local: SocketAddr,
}

impl UdpSocket {
    pub(super) fn new(shared: Arc<Shared>, handle: SocketHandle, local: SocketAddr) -> Self {
        Self {
            shared,
            handle,
            local,
        }
    }

    /// Our mesh address and the bound port: what peers send to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Send one datagram to a peer on the mesh.
    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<usize> {
        if data.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a {}-byte datagram does not fit the tunnel (at most {MAX_UDP_PAYLOAD})",
                    data.len()
                ),
            ));
        }
        if self.shared.lock().netmap.peer_by_ip(target.ip()).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is not a peer on the mesh", target.ip()),
            ));
        }
        let sent = poll_fn(|cx| {
            let mut state = self.shared.lock();
            let socket = state.netstack.udp_socket(self.handle);
            match socket.send_slice(data, IpEndpoint::from(target)) {
                Ok(()) => Poll::Ready(Ok(data.len())),
                Err(SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(SendError::Unaddressable) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cannot send to {target}"),
                ))),
            }
        })
        .await;
        self.shared.wake.notify_one();
        sent
    }

    /// Receive one datagram and who sent it. A datagram larger than `buf`
    /// is an error (and dropped).
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            let mut state = self.shared.lock();
            let socket = state.netstack.udp_socket(self.handle);
            match socket.recv_slice(buf) {
                Ok((n, meta)) => Poll::Ready(Ok((
                    n,
                    SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port),
                ))),
                Err(RecvError::Truncated) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the datagram is larger than the buffer",
                ))),
                Err(RecvError::Exhausted) => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.netstack.udp_socket(self.handle).close();
        state.netstack.remove(self.handle);
    }
}
