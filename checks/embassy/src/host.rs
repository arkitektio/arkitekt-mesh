//! The host's network as the embassy driver's [`Udp`] and [`Dial`]: UDP
//! and TCP through async-io (its own reactor thread), TLS through
//! futures-rustls (unverified, or against `$ARKITEKT_MESH_CA_FILE` or the
//! web's roots).

use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;

use async_io::Async;
use embedded_io_adapters::futures_03::FromFutures;
use embedded_io_async::{ErrorType, Read, Write};
use mesh_embassy::{Dial, DialError, Tls, Udp};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

pub struct HostUdp(Async<UdpSocket>);

impl HostUdp {
    pub fn bind() -> Self {
        Self(Async::<UdpSocket>::bind(([0, 0, 0, 0], 0)).expect("bind UDP"))
    }
}

impl Udp for HostUdp {
    type Error = std::io::Error;

    async fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        self.0.send_to(data, to).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.0.recv_from(buf).await
    }

    fn local_port(&self) -> u16 {
        self.0.get_ref().local_addr().map(|a| a.port()).unwrap_or(0)
    }

    fn local_endpoint(&self) -> Option<SocketAddr> {
        // Connecting a UDP socket sends nothing; it picks the route.
        let probe = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
        probe.connect(("192.0.2.1", 9)).ok()?;
        let ip = probe.local_addr().ok()?.ip();
        (!ip.is_unspecified()).then(|| SocketAddr::new(ip, self.local_port()))
    }
}

pub enum Conn {
    Plain(FromFutures<Async<TcpStream>>),
    Tls(Box<FromFutures<futures_rustls::client::TlsStream<Async<TcpStream>>>>),
}

impl ErrorType for Conn {
    type Error = std::io::Error;
}

impl Read for Conn {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        match self {
            Conn::Plain(c) => c.read(buf).await,
            Conn::Tls(c) => c.read(buf).await,
        }
    }
}

impl Write for Conn {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Conn::Plain(c) => c.write(buf).await,
            Conn::Tls(c) => c.write(buf).await,
        }
    }

    async fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Conn::Plain(c) => c.flush().await,
            Conn::Tls(c) => c.flush().await,
        }
    }
}

pub struct HostDial {
    verified: Arc<ClientConfig>,
    unverified: Arc<ClientConfig>,
}

impl HostDial {
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        match std::env::var("ARKITEKT_MESH_CA_FILE") {
            Ok(path) => {
                let pem = std::fs::read(&path).expect("the CA file");
                for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(&pem) {
                    let cert: CertificateDer<'static> = cert.expect("a PEM certificate");
                    roots.add(cert).expect("a CA certificate");
                }
            }
            Err(_) => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        let verified = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let unverified = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        Self {
            verified: Arc::new(verified),
            unverified: Arc::new(unverified),
        }
    }
}

impl Dial for HostDial {
    type Conn<'a> = Conn;

    async fn dial(&self, host: &str, port: u16, tls: Tls<'_>) -> Result<Conn, DialError> {
        let err = |e: std::io::Error| DialError(format!("{host}:{port}: {e}"));
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(err)?
            .next()
            .ok_or_else(|| DialError(format!("{host} does not resolve")))?;
        let tcp = Async::<TcpStream>::connect(addr).await.map_err(err)?;
        let (config, name) = match tls {
            Tls::None => return Ok(Conn::Plain(FromFutures::new(tcp))),
            Tls::Verify(name) => (self.verified.clone(), name),
            Tls::Unverified(name) => (self.unverified.clone(), name),
        };
        let name = ServerName::try_from(name.to_string())
            .map_err(|e| DialError(format!("{name}: {e}")))?;
        let stream = futures_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(err)?;
        Ok(Conn::Tls(Box::new(FromFutures::new(stream))))
    }
}

/// Accepts any certificate (signatures still checked).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
