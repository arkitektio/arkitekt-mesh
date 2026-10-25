//! The board's TLS on the host: streams from arkitekt-embassy's
//! `conn::open` (TLS 1.3 on embedded-tls, as the firmware has it) over the
//! host's TCP. The mesh driver drops a connection's `read` whenever a
//! packet is queued for it, so this is where a TLS that is not
//! cancel-safe would show.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use arkitekt_embassy::conn::{self, TlsBuffers, Transport, Verify};
use embassy_executor::Spawner;
use embedded_io_adapters::futures_03::FromFutures;
use embedded_nal_async::{AddrType, Dns, TcpConnect};
use mesh_embassy::{Dial, DialError, Tls};

/// The host's TCP as embedded-nal-async.
pub struct HostTcp;

impl TcpConnect for HostTcp {
    type Error = std::io::Error;
    type Connection<'a> = FromFutures<async_io::Async<std::net::TcpStream>>;

    async fn connect<'a>(
        &'a self,
        remote: SocketAddr,
    ) -> Result<Self::Connection<'a>, Self::Error> {
        Ok(FromFutures::new(
            async_io::Async::<std::net::TcpStream>::connect(remote).await?,
        ))
    }
}

/// The host's resolver as embedded-nal-async.
pub struct HostDns;

impl Dns for HostDns {
    type Error = std::io::Error;

    async fn get_host_by_name(
        &self,
        host: &str,
        addr_type: AddrType,
    ) -> Result<IpAddr, Self::Error> {
        (host, 0)
            .to_socket_addrs()?
            .map(|a| a.ip())
            .find(|ip| match addr_type {
                AddrType::IPv4 => ip.is_ipv4(),
                AddrType::IPv6 => ip.is_ipv6(),
                AddrType::Either => true,
            })
            .ok_or_else(|| std::io::Error::other(format!("{host} does not resolve")))
    }

    async fn get_host_by_address(
        &self,
        _addr: IpAddr,
        _result: &mut [u8],
    ) -> Result<usize, Self::Error> {
        Err(std::io::Error::other("no reverse lookups"))
    }
}

static TCP: HostTcp = HostTcp;

struct HostEntropy;

impl arkitekt_embassy::Entropy for HostEntropy {
    fn fill(&self, bytes: &mut [u8]) {
        mesh_core::random::fill(bytes)
    }
}

/// arkitekt-embassy's runtime, for its clock: certificates are checked
/// against the wall clock.
pub fn install_runtime(spawner: Spawner) {
    let runtime = arkitekt_embassy::runtime::Embassy::new(spawner.make_send(), HostEntropy);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    runtime.set_wall_clock(unix);
    let _ = arkitekt_spec::rt::install(Arc::new(runtime));
}

/// Streams through the board's TLS; verified ones against the lab CA
/// (`$ARKITEKT_MESH_CA_FILE`) or the CA given.
pub struct BoardDial {
    ca: Option<Vec<u8>>,
}

impl BoardDial {
    pub fn new() -> Self {
        let ca = std::env::var("ARKITEKT_MESH_CA_FILE").ok().map(|path| {
            let pem = std::fs::read(&path).expect("the CA file");
            let der: rustls_pki_types::CertificateDer<'static> =
                rustls_pki_types::pem::PemObject::from_pem_slice(&pem).expect("a PEM certificate");
            der.to_vec()
        });
        Self { ca }
    }
}

pub type BoardConn = Transport<'static, FromFutures<async_io::Async<std::net::TcpStream>>>;

impl Dial for BoardDial {
    type Conn<'a> = BoardConn;

    async fn dial(&self, host: &str, port: u16, tls: Tls<'_>) -> Result<BoardConn, DialError> {
        // The record buffers live as long as the connection may (a check).
        let buffers: &'static mut TlsBuffers = Box::leak(Box::default());
        let (secure, name, verify) = match tls {
            Tls::None => (false, host, Verify::Unverified),
            Tls::Verify(name) => (
                true,
                name,
                Verify::Ca(
                    self.ca
                        .clone()
                        .ok_or_else(|| DialError("no CA to verify with".into()))?,
                ),
            ),
            Tls::Unverified(name) => (true, name, Verify::Unverified),
        };
        // Dialed by the name the certificate is checked for (embedded-tls
        // takes the server name from the host it is given).
        let target = if secure { name } else { host };
        conn::open(&TCP, &HostDns, secure, target, port, &verify, buffers)
            .await
            .map_err(DialError)
    }
}
