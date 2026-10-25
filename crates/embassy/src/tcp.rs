//! TCP over the tunnel for the app: connections on the core's netstack,
//! as `embedded_io_async` streams and `embedded_nal_async::TcpConnect`
//! (with `Dns` answering from the netmap).

use core::future::poll_fn;
use core::net::{IpAddr, SocketAddr};
use core::task::Poll;

use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use embedded_nal_async::{AddrType, Dns, TcpConnect};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State;

use crate::Mesh;

/// Connections give up on a handshake after this long.
const CONNECT_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TcpError {
    #[error("the node is not on the mesh yet")]
    NotJoined,
    #[error("{0} is not a peer on the mesh")]
    NotAPeer(IpAddr),
    #[error("no such host on the mesh")]
    UnknownHost,
    #[error("the connection was refused")]
    Refused,
    #[error("the connection timed out")]
    TimedOut,
    #[error("the connection was reset")]
    Reset,
    #[error("no more sockets")]
    Exhausted,
}

impl embedded_io_async::Error for TcpError {
    fn kind(&self) -> ErrorKind {
        match self {
            TcpError::Refused => ErrorKind::ConnectionRefused,
            TcpError::TimedOut => ErrorKind::TimedOut,
            TcpError::Reset => ErrorKind::ConnectionReset,
            TcpError::NotAPeer(_) | TcpError::UnknownHost => ErrorKind::AddrNotAvailable,
            TcpError::NotJoined | TcpError::Exhausted => ErrorKind::Other,
        }
    }
}

/// A TCP connection over the mesh.
pub struct TcpStream<'m> {
    mesh: &'m Mesh,
    handle: SocketHandle,
    established: bool,
}

impl Mesh {
    /// Connect to `remote`, a peer's tailnet address.
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpStream<'_>, TcpError> {
        let handle = {
            let mut inner = self.inner.borrow_mut();
            let core = inner.core.as_mut().ok_or(TcpError::NotJoined)?;
            if core.netmap().peer_by_ip(remote.ip()).is_none() {
                return Err(TcpError::NotAPeer(remote.ip()));
            }
            core.netstack_mut()
                .connect(remote)
                .map_err(|_| TcpError::Exhausted)?
        };
        let mut stream = TcpStream {
            mesh: self,
            handle,
            established: false,
        };
        self.node_wake.signal(());
        let up = poll_fn(|cx| {
            let mut inner = self.inner.borrow_mut();
            let Some(core) = inner.core.as_mut() else {
                return Poll::Ready(Err(TcpError::Reset));
            };
            let socket = core.netstack_mut().socket(handle);
            match socket.state() {
                State::Established => Poll::Ready(Ok(())),
                State::Closed | State::TimeWait | State::Closing => {
                    Poll::Ready(Err(TcpError::Refused))
                }
                _ => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
        });
        match embassy_time::with_timeout(CONNECT_TIMEOUT, up).await {
            Ok(Ok(())) => {
                stream.established = true;
                Ok(stream)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TcpError::TimedOut),
        }
    }
}

impl ErrorType for TcpStream<'_> {
    type Error = TcpError;
}

impl Read for TcpStream<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TcpError> {
        poll_fn(|cx| {
            let mut inner = self.mesh.inner.borrow_mut();
            let Some(core) = inner.core.as_mut() else {
                return Poll::Ready(Err(TcpError::Reset));
            };
            let socket = core.netstack_mut().socket(self.handle);
            if socket.can_recv() {
                let n = socket.recv_slice(buf).map_err(|_| TcpError::Reset)?;
                drop(inner);
                // Receive-window space freed: let the node tell the peer.
                self.mesh.node_wake.signal(());
                return Poll::Ready(Ok(n));
            }
            if !socket.may_recv() {
                return Poll::Ready(Ok(0));
            }
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl Write for TcpStream<'_> {
    async fn write(&mut self, data: &[u8]) -> Result<usize, TcpError> {
        poll_fn(|cx| {
            let mut inner = self.mesh.inner.borrow_mut();
            let Some(core) = inner.core.as_mut() else {
                return Poll::Ready(Err(TcpError::Reset));
            };
            let socket = core.netstack_mut().socket(self.handle);
            if !socket.may_send() {
                return Poll::Ready(Err(TcpError::Reset));
            }
            if socket.can_send() {
                let n = socket.send_slice(data).map_err(|_| TcpError::Reset)?;
                drop(inner);
                self.mesh.node_wake.signal(());
                return Poll::Ready(Ok(n));
            }
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), TcpError> {
        Ok(())
    }
}

impl Drop for TcpStream<'_> {
    fn drop(&mut self) {
        let mut inner = self.mesh.inner.borrow_mut();
        if let Some(core) = inner.core.as_mut() {
            let socket = core.netstack_mut().socket(self.handle);
            if self.established {
                socket.close();
            } else {
                socket.abort();
            }
            core.close_socket(self.handle);
        }
        drop(inner);
        self.mesh.node_wake.signal(());
    }
}

impl TcpConnect for Mesh {
    type Error = TcpError;
    type Connection<'a> = TcpStream<'a>;

    async fn connect<'a>(&'a self, remote: SocketAddr) -> Result<TcpStream<'a>, TcpError> {
        Mesh::connect(self, remote).await
    }
}

impl Dns for Mesh {
    type Error = TcpError;

    async fn get_host_by_name(&self, host: &str, addr_type: AddrType) -> Result<IpAddr, TcpError> {
        let ip = self.resolve(host).ok_or(TcpError::UnknownHost)?;
        match (addr_type, ip) {
            (AddrType::IPv4, IpAddr::V6(_)) | (AddrType::IPv6, IpAddr::V4(_)) => {
                Err(TcpError::UnknownHost)
            }
            _ => Ok(ip),
        }
    }

    async fn get_host_by_address(
        &self,
        _addr: IpAddr,
        _result: &mut [u8],
    ) -> Result<usize, TcpError> {
        Err(TcpError::UnknownHost)
    }
}
