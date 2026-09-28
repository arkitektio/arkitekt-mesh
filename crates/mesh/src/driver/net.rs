//! Connections for the driver: TCP, optionally TLS (never offering ALPN,
//! since control and DERP both take over a plain HTTP/1.1 connection), and
//! just enough HTTP/1.1 to fetch a key and perform an upgrade.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

pub type BoxIo = Box<dyn Io>;

/// A parsed `http(s)://host[:port]` base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl {
    pub https: bool,
    pub host: String,
    pub port: u16,
}

impl BaseUrl {
    pub fn parse(url: &str) -> io::Result<Self> {
        let bad = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not an http(s) url: {url}"),
            )
        };
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(bad());
        };
        let authority = rest.split('/').next().unwrap_or_default();
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, after) = v6.split_once(']').ok_or_else(bad)?;
            let port = after
                .strip_prefix(':')
                .map(str::parse)
                .transpose()
                .map_err(|_| bad())?;
            (host.to_owned(), port.unwrap_or(default_port))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_owned(), port.parse().map_err(|_| bad())?),
                None => (authority.to_owned(), default_port),
            }
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self { https, host, port })
    }

    /// `host[:port]` for a Host header (the port only when not the default).
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// How to secure a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    None,
    Verify,
    /// Encrypt but accept any certificate (Noise authenticates control; the
    /// DERP map marks test servers `InsecureForTests`).
    NoVerify,
}

/// Connect to `host:port`; over TLS, the certificate must name `host`.
pub async fn connect(host: &str, port: u16, tls: Tls) -> io::Result<BoxIo> {
    connect_named(host, port, tls, host).await
}

/// Connect to `dial:port`, checking the certificate against `name` (DERP
/// nodes are dialed by IP but certified for their hostname).
pub async fn connect_named(dial: &str, port: u16, tls: Tls, name: &str) -> io::Result<BoxIo> {
    // An IP literal needs no resolver (tokio's would start a thread pool).
    let tcp = match dial.parse::<IpAddr>() {
        Ok(ip) => TcpStream::connect((ip, port)).await?,
        Err(_) => TcpStream::connect((dial, port)).await?,
    };
    tcp.set_nodelay(true)?;
    if tls == Tls::None {
        return Ok(Box::new(tcp));
    }
    let host = name;
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
    };
    let connector = tokio_rustls::TlsConnector::from(tls_config(tls == Tls::Verify));
    Ok(Box::new(connector.connect(name, tcp).await?))
}

/// The process's TLS provider, else ring (feature `ring`).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return provider.clone();
    }
    #[cfg(feature = "ring")]
    return Arc::new(rustls::crypto::ring::default_provider());
    #[cfg(not(feature = "ring"))]
    panic!("no rustls CryptoProvider: install one before starting a mesh node");
}

/// Certificates trusted besides the public web PKI: a private CA, e.g. a
/// self-hosted control server whose DERP nodes carry its own certificates.
static EXTRA_ROOTS: Mutex<Vec<CertificateDer<'static>>> = Mutex::new(Vec::new());

/// Whether the public web PKI roots are trusted too (the default).
static PUBLIC_ROOTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Trust only the roots added with [`add_trust_roots_pem`], not the ~150
/// public ones: for a private deployment on a small device, where every
/// verified connection would otherwise hold its own copy of them.
pub fn trust_public_roots(trust: bool) {
    PUBLIC_ROOTS.store(trust, std::sync::atomic::Ordering::Relaxed);
}

/// The environment variable naming a PEM file of extra CA certificates
/// (read once, when the first verified connection is made).
pub const CA_FILE_ENV: &str = "ARKITEKT_MESH_CA_FILE";

/// Also trust the CA certificates in `pem` for verified connections (DERP
/// nodes; control is authenticated by Noise). Process-wide, for every node.
/// Returns how many certificates were added.
pub fn add_trust_roots_pem(pem: &[u8]) -> io::Result<usize> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad PEM: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates in the PEM",
        ));
    }
    let n = certs.len();
    EXTRA_ROOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .extend(certs);
    Ok(n)
}

/// Load `$ARKITEKT_MESH_CA_FILE`, once.
fn load_ca_file() {
    static LOADED: OnceLock<()> = OnceLock::new();
    LOADED.get_or_init(|| {
        let Some(path) = std::env::var_os(CA_FILE_ENV).filter(|p| !p.is_empty()) else {
            return;
        };
        match std::fs::read(&path).and_then(|pem| add_trust_roots_pem(&pem)) {
            Ok(n) => tracing::info!("trusting {n} extra CA certificate(s) from {path:?}"),
            Err(e) => tracing::warn!("could not load {CA_FILE_ENV}={path:?}: {e}"),
        }
    });
}

fn tls_config(verify: bool) -> Arc<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("the provider supports the default versions");
    let config = if verify {
        load_ca_file();
        let mut roots = rustls::RootCertStore::empty();
        if PUBLIC_ROOTS.load(std::sync::atomic::Ordering::Relaxed) {
            roots.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
        }
        for cert in EXTRA_ROOTS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            if let Err(e) = roots.add(cert.clone()) {
                tracing::warn!("ignoring an extra CA certificate: {e}");
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider())))
            .with_no_client_auth()
    };
    // No ALPN: the server must stay on HTTP/1.1 to hand the connection over.
    Arc::new(config)
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A response head, and whatever arrived after it.
#[derive(Debug)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub rest: Vec<u8>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read a response head. Bytes past it (the start of the protocol after an
/// upgrade, or the body) are returned in [`Head::rest`], never lost.
pub async fn read_head(io: &mut (impl AsyncRead + Unpin)) -> io::Result<Head> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response head too large",
            ));
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before a response",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let text = std::str::from_utf8(&buf[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response head is not text"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed status line"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Ok(Head {
        status,
        headers,
        rest: buf[end + 4..].to_vec(),
    })
}

/// `GET` a small resource; returns the status and body.
pub async fn get(base: &BaseUrl, path: &str) -> io::Result<(u16, Vec<u8>)> {
    let tls = if base.https { Tls::Verify } else { Tls::None };
    let mut io = connect(&base.host, base.port, tls).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: arkitekt-mesh\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        base.authority()
    );
    io.write_all(request.as_bytes()).await?;
    let head = read_head(&mut io).await?;
    let mut body = head.rest.clone();
    io.read_to_end(&mut body).await.or_else(|e| {
        // Some TLS servers close without close_notify; the body is complete.
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Ok(0)
        } else {
            Err(e)
        }
    })?;
    if head
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        body = dechunk(&body)?;
    } else if let Some(len) = head
        .header("content-length")
        .and_then(|l| l.parse::<usize>().ok())
    {
        body.truncate(len);
    }
    Ok((head.status, body))
}

fn dechunk(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed chunked body");
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_text = std::str::from_utf8(&body[..line_end]).map_err(|_| bad())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad())?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(body.get(..size).ok_or_else(bad)?);
        body = body.get(size + 2..).ok_or_else(bad)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        let u = BaseUrl::parse("https://mesh.example.com").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port),
            (true, "mesh.example.com", 443)
        );
        assert_eq!(u.authority(), "mesh.example.com");
        let u = BaseUrl::parse("http://127.0.0.1:37767/").unwrap();
        assert_eq!((u.https, u.port), (false, 37767));
        assert_eq!(u.authority(), "127.0.0.1:37767");
        let u = BaseUrl::parse("http://[::1]:8080").unwrap();
        assert_eq!(
            (u.host.as_str(), u.authority()),
            ("::1", "[::1]:8080".to_owned())
        );
        assert!(BaseUrl::parse("ftp://x").is_err());
    }

    #[test]
    fn chunked_bodies() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n1;x\r\n!\r\n0\r\n\r\n").unwrap(),
            b"hello!"
        );
    }

    #[tokio::test]
    async fn heads_keep_what_follows() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n\x01\x02")
            .await
            .unwrap();
        let head = read_head(&mut b).await.unwrap();
        assert_eq!(head.status, 101);
        assert_eq!(head.header("upgrade"), Some("DERP"));
        assert_eq!(head.rest, vec![1, 2]);
    }
}

#[cfg(test)]
mod trust_tests {
    use super::*;

    #[test]
    fn extra_roots_come_from_pem() {
        use base64::Engine;
        // Only the PEM framing is parsed here; the DER is checked when a
        // connection is verified against it.
        let der = base64::engine::general_purpose::STANDARD.encode([0x30u8; 48]);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{der}\n-----END CERTIFICATE-----\n");
        assert_eq!(add_trust_roots_pem(pem.as_bytes()).unwrap(), 1);
        assert!(add_trust_roots_pem(b"not pem").is_err());
    }
}
