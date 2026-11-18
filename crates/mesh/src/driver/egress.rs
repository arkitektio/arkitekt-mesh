//! The way out of a network that lets nothing out but through its HTTP
//! proxy: control and DERP are then dialed through a `CONNECT` tunnel, as
//! `HTTPS_PROXY` (or `ALL_PROXY`) names it and `NO_PROXY` exempts.
//!
//! Only connections over TLS take the proxy (a plain `http://` control
//! server is a local one), and never ones to this host itself. UDP has no
//! proxy: behind one the node usually runs over DERP alone.

use std::io;
use std::net::IpAddr;
use std::sync::OnceLock;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// An HTTP proxy that tunnels with `CONNECT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// `user:password`, sent as Basic credentials.
    pub credentials: Option<String>,
}

/// What the environment says about proxies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Egress {
    proxy: Option<Proxy>,
    /// `NO_PROXY`'s entries, lowercase, without ports or leading dots.
    exempt: Vec<String>,
}

impl Proxy {
    /// `http://[user:password@]host[:port]`, or `host:port`. Other schemes
    /// (`socks5://`, a proxy that is itself behind TLS) are not spoken.
    pub fn parse(url: &str) -> Result<Self, String> {
        let url = url.trim();
        let rest = match url.split_once("://") {
            Some(("http", rest)) => rest,
            Some((scheme, _)) => return Err(format!("{scheme}:// proxies are not supported")),
            None => url,
        };
        let authority = rest.split('/').next().unwrap_or_default();
        let (credentials, address) = match authority.rsplit_once('@') {
            Some((userinfo, address)) => (Some(percent_decode(userinfo)), address),
            None => (None, authority),
        };
        let bad = || format!("not a proxy address: {address:?}");
        let (host, port) = if let Some(v6) = address.strip_prefix('[') {
            let (host, after) = v6.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().map_err(|_| bad())?,
                None => 80,
            };
            (host, port)
        } else {
            match address.rsplit_once(':') {
                Some((host, port)) => (host, port.parse().map_err(|_| bad())?),
                None => (address, 80),
            }
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            credentials,
        })
    }

    /// `host:port`, as errors name the proxy (never its credentials).
    pub fn address(&self) -> String {
        join(&self.host, self.port)
    }

    /// A connection to `host:port` through this proxy: what comes back is
    /// the tunnel, as if dialed directly.
    pub async fn tunnel(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let via = self.address();
        let mut tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| context(e, format!("connecting to the proxy {via}")))?;
        let target = join(host, port);
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(credentials) = &self.credentials {
            let basic = base64::engine::general_purpose::STANDARD.encode(credentials);
            request.push_str(&format!("Proxy-Authorization: Basic {basic}\r\n"));
        }
        request.push_str("\r\n");
        tcp.write_all(request.as_bytes())
            .await
            .map_err(|e| context(e, format!("asking the proxy {via} for {target}")))?;
        let head = super::net::read_head(&mut tcp)
            .await
            .map_err(|e| context(e, format!("the proxy {via}, asked for {target}")))?;
        let refused = |why: String| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("the proxy {via} did not connect to {target}: {why}"),
            )
        };
        match head.status {
            200..=299 => {}
            407 if self.credentials.is_some() => {
                return Err(refused(
                    "it refused the credentials (HTTP 407; only Basic is spoken)".into(),
                ))
            }
            407 => {
                return Err(refused(
                    "it wants credentials (HTTP 407): give them in the proxy url, \
                     http://user:password@host:port"
                        .into(),
                ))
            }
            status => return Err(refused(format!("HTTP {status}"))),
        }
        // The far end speaks second (TLS): nothing may follow the head.
        if !head.rest.is_empty() {
            return Err(refused("it sent data before the tunnel was used".into()));
        }
        Ok(tcp)
    }
}

impl Egress {
    /// From the variables every HTTP client reads: `HTTPS_PROXY`, else
    /// `ALL_PROXY`, and `NO_PROXY` (each also in lowercase, which wins).
    pub fn from_env() -> Self {
        let var = |names: &[&str]| {
            names
                .iter()
                .filter_map(|name| std::env::var(name).ok())
                .find(|value| !value.trim().is_empty())
        };
        let proxy = var(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]);
        let exempt = var(&["no_proxy", "NO_PROXY"]).unwrap_or_default();
        Self::new(proxy.as_deref(), &exempt)
    }

    /// `proxy` as its variable gives it (one that cannot be used is warned
    /// of and left out), `no_proxy` as `NO_PROXY` lists exemptions.
    pub fn new(proxy: Option<&str>, no_proxy: &str) -> Self {
        let proxy = proxy.and_then(|url| match Proxy::parse(url) {
            Ok(proxy) => Some(proxy),
            Err(why) => {
                tracing::warn!("ignoring the proxy from the environment: {why}");
                None
            }
        });
        let exempt = no_proxy
            .split(',')
            .map(|entry| {
                let entry = entry.trim().to_ascii_lowercase();
                let entry = entry.trim_start_matches("*.").trim_start_matches('.');
                // `host:port` exempts the host; an IPv6 address keeps its colons.
                match entry.rsplit_once(':') {
                    Some((host, port))
                        if !host.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        host.to_owned()
                    }
                    _ => entry.trim_matches(['[', ']']).to_owned(),
                }
            })
            .filter(|entry| !entry.is_empty())
            .collect();
        Self { proxy, exempt }
    }

    /// The proxy a connection to `host` goes through, if any. This host
    /// itself is always reached directly.
    pub fn proxy_for(&self, host: &str) -> Option<&Proxy> {
        let proxy = self.proxy.as_ref()?;
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok();
        if host == "localhost" || ip.is_some_and(|ip| ip.to_canonical().is_loopback()) {
            return None;
        }
        let exempt = self.exempt.iter().any(|entry| {
            entry == "*"
                || *entry == host
                || host
                    .strip_suffix(entry.as_str())
                    .is_some_and(|rest| ip.is_none() && rest.ends_with('.'))
                || ip.is_some_and(|ip| in_network(ip, entry))
        });
        (!exempt).then_some(proxy)
    }
}

/// The process's egress, read from the environment once.
pub fn egress() -> &'static Egress {
    static EGRESS: OnceLock<Egress> = OnceLock::new();
    EGRESS.get_or_init(|| {
        let egress = Egress::from_env();
        if let Some(proxy) = &egress.proxy {
            tracing::info!(
                "control and DERP go through the proxy {} (from the environment)",
                proxy.address()
            );
        }
        egress
    })
}

/// Whether `ip` is in `network`, written `address/bits`.
fn in_network(ip: IpAddr, network: &str) -> bool {
    let Some((address, bits)) = network.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(bits)) = (address.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    let masked = |value: u128, width: u32| match width.checked_sub(bits) {
        Some(0) => Some(value),
        Some(host_bits) if host_bits < width => Some(value >> host_bits),
        Some(_) => Some(0),
        None => None,
    };
    match (ip.to_canonical(), address) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            masked(u32::from(ip).into(), 32) == masked(u32::from(net).into(), 32) && bits <= 32
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            masked(ip.into(), 128) == masked(net.into(), 128) && bits <= 128
        }
        _ => false,
    }
}

fn join(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `%40` and the like, as credentials in a url are written.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%')
            .then(|| text.get(i + 1..i + 3))
            .flatten()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn context(e: io::Error, what: String) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn no_proxy_exempts_names_domains_and_networks() {
        let egress = Egress::new(
            Some("http://user:p%40ss@proxy.lab:3128"),
            "localhost, .internal.example, 10.0.0.0/8, derp9.example.com:443",
        );
        let proxy = egress.proxy_for("go.arkitekt.live").expect("proxied");
        assert_eq!((proxy.host.as_str(), proxy.port), ("proxy.lab", 3128));
        assert_eq!(proxy.credentials.as_deref(), Some("user:p@ss"));
        for direct in [
            "hub.internal.example",
            "internal.example",
            "10.1.2.3",
            "derp9.example.com",
            "127.0.0.1",
            "::1",
            "localhost",
        ] {
            assert_eq!(egress.proxy_for(direct), None, "{direct}");
        }
        // A suffix is a domain's, not any name's ending.
        assert!(egress.proxy_for("notinternal.example").is_some());
        assert!(egress.proxy_for("11.0.0.1").is_some());
        assert_eq!(Egress::new(None, "").proxy_for("go.arkitekt.live"), None);
        assert!(Proxy::parse("socks5://proxy.lab:1080").is_err());
    }

    /// The tunnel asks for the target by name, with the credentials, and
    /// hands over the connection once the proxy says 200.
    #[tokio::test]
    async fn a_tunnel_is_asked_for_by_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(tcp.read_u8().await.unwrap());
            }
            tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut ping = [0u8; 4];
            tcp.read_exact(&mut ping).await.unwrap();
            tcp.write_all(&ping).await.unwrap();
            String::from_utf8(head).unwrap()
        });
        let proxy = Proxy::parse(&format!("http://me:secret@127.0.0.1:{port}")).unwrap();
        let mut tunnel = proxy.tunnel("derp1.example.com", 443).await.unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        tunnel.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ping");
        let head = served.await.unwrap();
        assert!(
            head.starts_with("CONNECT derp1.example.com:443 HTTP/1.1\r\n"),
            "{head}"
        );
        // base64("me:secret")
        assert!(
            head.contains("Proxy-Authorization: Basic bWU6c2VjcmV0\r\n"),
            "{head}"
        );
    }
}
