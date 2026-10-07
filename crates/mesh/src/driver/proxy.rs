//! The local HTTP proxy into the mesh, as meshd serves it: `CONNECT
//! host:port` tunnels (TLS, websockets) and absolute-form `http://` requests,
//! with every upstream connection dialed through the node. Responses stream
//! through as they arrive. HTTP only: there is deliberately no SOCKS.
//!
//! Upstream connections of `http://` requests are kept and used again, per
//! host: a connection over the mesh costs a round trip (and, to a peer not
//! spoken to yet, a handshake) that a request for one chunk of an array
//! should not pay each time.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

type Body = BoxBody<Bytes, hyper::Error>;

/// How long an unused upstream connection is kept: well under the two
/// minutes after which the mesh's TCP gives up on a silent peer.
const IDLE_UPSTREAM: Duration = Duration::from_secs(60);
/// Unused upstream connections kept per host.
const IDLE_PER_HOST: usize = 16;
/// The buffer, each way, of a tunnel's copy.
const TUNNEL_BUFFER: usize = 64 * 1024;

/// Opens connections to `host:port` on the mesh.
pub trait Dial: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn dial(&self, host: &str, port: u16) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Serve the proxy on a free loopback port. Returns its url and the task
/// running it; aborting the task closes every proxied connection.
pub async fn serve<D: Dial>(dialer: D) -> io::Result<(String, JoinHandle<()>)> {
    serve_on(dialer, TcpListener::bind("127.0.0.1:0").await?)
}

/// Serve the proxy on `listener` (see [`serve`]).
pub fn serve_on<D: Dial>(dialer: D, listener: TcpListener) -> io::Result<(String, JoinHandle<()>)> {
    let url = format!("http://{}", listener.local_addr()?);
    let dialer = Arc::new(dialer);
    let upstream = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(IDLE_UPSTREAM)
        .pool_max_idle_per_host(IDLE_PER_HOST)
        .http1_preserve_header_case(true)
        .build(Connector(dialer.clone()));
    let proxy = Arc::new(Proxy { dialer, upstream });
    let task = tokio::spawn(async move {
        // Owned here, so aborting the proxy also aborts its connections.
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(serve_connection(proxy.clone(), stream));
                    }
                    Err(e) => {
                        tracing::warn!("the mesh proxy could not accept a connection: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    Ok((url, task))
}

struct Proxy<D: Dial> {
    dialer: Arc<D>,
    /// For `http://` requests: it keeps the connections it made, by host.
    upstream: Client<Connector<D>, Incoming>,
}

/// Dials the host of a request's url, for [`Client`].
struct Connector<D>(Arc<D>);

impl<D> Clone for Connector<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<D: Dial> tower_service::Service<Uri> for Connector<D> {
    type Response = Upstream<D::Stream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let dialer = self.0.clone();
        Box::pin(async move {
            let (host, port) = target(&uri, 80).map_err(|(_, why)| io::Error::other(why))?;
            Ok(Upstream(TokioIo::new(dialer.dial(&host, port).await?)))
        })
    }
}

/// A connection over the mesh, as [`Client`] holds it.
struct Upstream<S>(TokioIo<S>);

impl<S> Connection for Upstream<S> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for Upstream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> hyper::rt::Write for Upstream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

async fn serve_connection<D: Dial>(proxy: Arc<Proxy<D>>, stream: TcpStream) {
    let service = hyper::service::service_fn(move |req| handle(proxy.clone(), req));
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
    {
        tracing::debug!("mesh proxy connection ended: {e}");
    }
}

async fn handle<D: Dial>(
    proxy: Arc<Proxy<D>>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let response = if req.method() == Method::CONNECT {
        tunnel(&*proxy.dialer, req).await
    } else {
        forward(&proxy.upstream, req).await
    };
    Ok(response.unwrap_or_else(|(status, message)| error(status, message)))
}

type Failure = (StatusCode, String);

/// `CONNECT host:port`: dial, answer 200, then splice the two connections.
async fn tunnel<D: Dial>(dialer: &D, req: Request<Incoming>) -> Result<Response<Body>, Failure> {
    let (host, port) = target(req.uri(), 443)?;
    let mut upstream = dial(dialer, &host, port).await?;
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(client) => {
                let mut client = TokioIo::new(client);
                let copied = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut upstream,
                    TUNNEL_BUFFER,
                    TUNNEL_BUFFER,
                );
                if let Err(e) = copied.await {
                    tracing::debug!("mesh tunnel to {host}:{port} ended: {e}");
                }
            }
            Err(e) => tracing::debug!("mesh tunnel to {host}:{port} was not upgraded: {e}"),
        }
    });
    Ok(Response::new(empty()))
}

/// An absolute-form `http://` request: send it over a connection to its
/// host (one kept from an earlier request, or a new one) and stream the
/// response back. Connections are kept by host, so a client re-using its
/// proxy connection for another host still ends up in the right place.
async fn forward<D: Dial>(
    upstream: &Client<Connector<D>, Incoming>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Failure> {
    if req.uri().scheme_str() != Some("http") {
        return Err((
            StatusCode::BAD_REQUEST,
            "the mesh proxy takes CONNECT and absolute http:// requests".into(),
        ));
    }
    let (host, port) = target(req.uri(), 80)?;

    // The url stays absolute (it names the connection to use); the client
    // sends it in origin form, with the Host header if there is none.
    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let response = upstream
        .request(Request::from_parts(parts, body))
        .await
        .map_err(|e| {
            // The cause (e.g. that no peer has this name) is what helps.
            let mut cause: &dyn std::error::Error = &e;
            while let Some(source) = cause.source() {
                cause = source;
            }
            tracing::debug!("the mesh could not reach {host}:{port}: {cause}");
            (StatusCode::BAD_GATEWAY, format!("{host}:{port}: {cause}"))
        })?;

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, body.boxed()))
}

fn target(uri: &Uri, default_port: u16) -> Result<(String, u16), Failure> {
    let authority = uri.authority().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("no host to proxy to in {uri}"),
        )
    })?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    Ok((
        host.to_owned(),
        authority.port_u16().unwrap_or(default_port),
    ))
}

async fn dial<D: Dial>(dialer: &D, host: &str, port: u16) -> Result<D::Stream, Failure> {
    dialer.dial(host, port).await.map_err(|e| {
        tracing::debug!("the mesh could not reach {host}:{port}: {e}");
        (StatusCode::BAD_GATEWAY, format!("{host}:{port}: {e}"))
    })
}

/// Drop the headers that describe one connection, not the message.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn error(status: StatusCode, message: String) -> Response<Body> {
    let body = Full::new(Bytes::from(message)).map_err(|never| match never {});
    let mut response = Response::new(body.boxed());
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Dials names from a table on loopback, like the node resolves peers.
    struct Table(HashMap<&'static str, SocketAddr>);

    impl Dial for Table {
        type Stream = TcpStream;

        async fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            let addr = self.0.get(host).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no peer named {host}"))
            })?;
            assert_eq!(port, 80, "the port from the request is dialed");
            TcpStream::connect(addr).await
        }
    }

    /// An http server answering with `name`, the path and the Host header,
    /// streamed in chunks.
    async fn server(name: &'static str) -> SocketAddr {
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default();
            let text = format!("{name} {} {host}", req.uri());
            let chunks: Vec<Result<String, Infallible>> = text
                .split_inclusive(' ')
                .map(|s| Ok(s.to_owned()))
                .collect();
            axum::body::Body::from_stream(futures::stream::iter(chunks))
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    async fn echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        addr
    }

    async fn proxy(table: Table) -> String {
        serve(table).await.unwrap().0
    }

    fn client(proxy: &str) -> reqwest::Client {
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(proxy).unwrap())
            .build()
            .unwrap()
    }

    async fn get(client: &reqwest::Client, url: &str) -> String {
        client.get(url).send().await.unwrap().text().await.unwrap()
    }

    #[tokio::test]
    async fn forwards_absolute_requests_to_each_host() {
        let alpha = server("alpha").await;
        let beta = server("beta").await;
        let proxy = proxy(Table(HashMap::from([
            ("alpha", alpha),
            ("beta.tail", beta),
        ])))
        .await;
        let client = client(&proxy);

        // One client, so the proxy connection is re-used across hosts.
        for _ in 0..2 {
            assert_eq!(
                get(&client, "http://alpha/x?y=1").await,
                "alpha /x?y=1 alpha"
            );
            assert_eq!(get(&client, "http://beta.tail/").await, "beta / beta.tail");
        }
    }

    #[tokio::test]
    async fn unknown_hosts_are_a_bad_gateway() {
        let proxy = proxy(Table(HashMap::new())).await;
        let response = client(&proxy).get("http://nowhere/").send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        assert!(response
            .text()
            .await
            .unwrap()
            .contains("no peer named nowhere"));
    }

    /// Counts the connections made.
    struct Counting(Table, Arc<std::sync::atomic::AtomicUsize>);

    impl Dial for Counting {
        type Stream = TcpStream;

        async fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.dial(host, port).await
        }
    }

    #[tokio::test]
    async fn upstream_connections_are_kept_per_host() {
        let alpha = server("alpha").await;
        let beta = server("beta").await;
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let table = Table(HashMap::from([("alpha", alpha), ("beta.tail", beta)]));
        let proxy = serve(Counting(table, dials.clone())).await.unwrap().0;

        // Each request on a proxy connection of its own, as clients that
        // keep none make them.
        for _ in 0..5 {
            assert_eq!(get(&client(&proxy), "http://alpha/").await, "alpha / alpha");
            assert_eq!(
                get(&client(&proxy), "http://beta.tail/").await,
                "beta / beta.tail"
            );
        }
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    async fn connect(proxy: &str, target: &str) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(proxy.trim_start_matches("http://"))
            .await
            .unwrap();
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        (stream, String::from_utf8(head).unwrap())
    }

    #[tokio::test]
    async fn connect_tunnels_bytes_both_ways() {
        let echo = echo().await;
        let proxy = proxy(Table(HashMap::from([("echo", echo)]))).await;

        let (mut stream, head) = connect(&proxy, "echo:80").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        stream.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ping");
    }

    #[tokio::test]
    async fn connect_to_an_unknown_host_fails() {
        let proxy = proxy(Table(HashMap::new())).await;
        let (_, head) = connect(&proxy, "nowhere:80").await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    }
}
