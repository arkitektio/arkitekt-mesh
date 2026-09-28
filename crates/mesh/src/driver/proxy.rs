//! The local HTTP proxy into the mesh, as meshd serves it: `CONNECT
//! host:port` tunnels (TLS, websockets) and absolute-form `http://` requests,
//! with every upstream connection dialed through the node. Responses stream
//! through as they arrive. HTTP only: there is deliberately no SOCKS.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

type Body = BoxBody<Bytes, hyper::Error>;

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
    let task = tokio::spawn(async move {
        // Owned here, so aborting the proxy also aborts its connections.
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(serve_connection(dialer.clone(), stream));
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

async fn serve_connection<D: Dial>(dialer: Arc<D>, stream: TcpStream) {
    let service = hyper::service::service_fn(move |req| handle(dialer.clone(), req));
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
    dialer: Arc<D>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let response = if req.method() == Method::CONNECT {
        tunnel(&*dialer, req).await
    } else {
        forward(&*dialer, req).await
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
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                    tracing::debug!("mesh tunnel to {host}:{port} ended: {e}");
                }
            }
            Err(e) => tracing::debug!("mesh tunnel to {host}:{port} was not upgraded: {e}"),
        }
    });
    Ok(Response::new(empty()))
}

/// An absolute-form `http://` request: dial, send it in origin form and
/// stream the response back. One upstream connection per request, so a
/// client re-using its proxy connection for another host still ends up in
/// the right place.
async fn forward<D: Dial>(dialer: &D, req: Request<Incoming>) -> Result<Response<Body>, Failure> {
    if req.uri().scheme_str() != Some("http") {
        return Err((
            StatusCode::BAD_REQUEST,
            "the mesh proxy takes CONNECT and absolute http:// requests".into(),
        ));
    }
    let (host, port) = target(req.uri(), 80)?;
    let upstream = dial(dialer, &host, port).await?;

    let (mut parts, body) = req.into_parts();
    let authority = parts.uri.authority().cloned();
    parts.uri = parts
        .uri
        .path_and_query()
        .map(|pq| Uri::from(pq.clone()))
        .unwrap_or_else(|| Uri::from_static("/"));
    strip_hop_by_hop(&mut parts.headers);
    if let Some(value) = authority.and_then(|a| HeaderValue::from_str(a.as_str()).ok()) {
        parts.headers.entry(header::HOST).or_insert(value);
    }

    let bad_gateway = |e: hyper::Error| (StatusCode::BAD_GATEWAY, format!("{host}:{port}: {e}"));
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(bad_gateway)?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("mesh upstream connection ended: {e}");
        }
    });
    let response = sender
        .send_request(Request::from_parts(parts, body))
        .await
        .map_err(bad_gateway)?;

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
