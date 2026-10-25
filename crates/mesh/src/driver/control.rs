//! The control client: `GET /key`, the ts2021 upgrade, Noise, then
//! HTTP/2 (prior knowledge) for register and map requests.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::net::{self, BaseUrl, BoxIo, Tls};
use crate::control::api::{self, ApiError, Call, MapFrames, MAX_MAP_FRAME};
use crate::control::noise::{ClientHandshake, NoiseStream, Transport, RESPONSE_LEN};
use crate::control::types::{
    MapRequest, MapResponse, RegisterRequest, RegisterResponse, CAPABILITY_VERSION,
};
use crate::keys::{MachinePublic, NodePublic, PrivateKey};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("control: {0}")]
    Io(#[from] io::Error),
    #[error("control: {0}")]
    Noise(#[from] crate::control::noise::NoiseError),
    #[error("control: http/2: {0}")]
    H2(#[from] h2::Error),
    #[error("control: {0}")]
    Protocol(String),
}

fn protocol(msg: impl Into<String>) -> ControlError {
    ControlError::Protocol(msg.into())
}

impl From<ApiError> for ControlError {
    fn from(e: ApiError) -> Self {
        ControlError::Protocol(e.0)
    }
}

/// An authenticated HTTP/2 connection to the control server.
#[derive(Clone)]
pub struct ControlClient {
    base: BaseUrl,
    send: h2::client::SendRequest<Bytes>,
    /// Drives the connection; aborted when the last clone is dropped, so a
    /// failed or abandoned start does not leave a connection (and its
    /// buffers) behind until the server hangs up.
    _connection: Arc<AbortOnDrop>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ControlClient {
    pub async fn connect(url: &str, machine: &PrivateKey) -> Result<Self, ControlError> {
        let base = BaseUrl::parse(url)?;
        let server_key = server_key(&base).await?;

        let tls = if base.https { Tls::NoVerify } else { Tls::None };
        let mut io = net::connect(&base.host, base.port, tls).await?;
        let (handshake, init) = ClientHandshake::start(machine, &server_key, CAPABILITY_VERSION)?;
        io.write_all(&api::upgrade_request(&base.authority(), &init))
            .await?;
        let head = net::read_head(&mut io).await?;
        if head.status != 101 {
            return Err(protocol(format!(
                "the upgrade to ts2021 failed with HTTP {}",
                head.status
            )));
        }
        // The server corks its answer: the response may ride with the head.
        let mut buf = head.rest;
        while buf.len() < 3 {
            read_more(&mut io, &mut buf).await?;
        }
        let want = ClientHandshake::response_len(&buf[..3].try_into().expect("3"));
        if want > 4096 {
            return Err(protocol("oversized handshake response"));
        }
        while buf.len() < want {
            read_more(&mut io, &mut buf).await?;
        }
        let transport = handshake.finish(&buf[..want])?;
        if want != RESPONSE_LEN {
            return Err(protocol("unexpected handshake response length"));
        }
        buf.drain(..want);

        let noise = NoiseIo::new(io, transport, buf)?;
        let (send, connection) = h2::client::Builder::new()
            // Small windows bound what control can buffer in us ahead of
            // our reading (memory matters on small devices).
            .initial_window_size(64 << 10)
            .initial_connection_window_size(64 << 10)
            .handshake::<_, Bytes>(noise)
            .await?;
        let connection = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("control connection ended: {e}");
            }
        });
        Ok(Self {
            base,
            send,
            _connection: Arc::new(AbortOnDrop(connection)),
        })
    }

    async fn send(&self, call: &Call) -> Result<(u16, h2::RecvStream), ControlError> {
        let uri = format!("https://{}{}", self.base.authority(), call.path);
        let mut request = http::Request::builder().method(call.method).uri(uri);
        for (name, value) in call.headers() {
            request = request.header(name, value);
        }
        let request = request.body(()).map_err(|e| protocol(e.to_string()))?;
        let mut send = self.send.clone().ready().await?;
        let (response, mut stream) = send.send_request(request, false)?;
        stream.send_data(Bytes::from(call.body.clone()), true)?;
        let response = response.await?;
        Ok((response.status().as_u16(), response.into_body()))
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, ControlError> {
        let (status, mut stream) = self.send(&Call::register(req)).await?;
        let body = read_all(&mut stream).await?;
        Ok(api::parse_register(status, &body)?)
    }

    /// A JSON RPC in Go's style: a GET with a JSON body (the tailnet-lock
    /// endpoints under `/machine/tka/`). Responses are capped at 10 MiB.
    pub async fn call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        node_key: &NodePublic,
        req: &Req,
    ) -> Result<Resp, ControlError> {
        let (status, mut stream) = self.send(&Call::rpc(path, node_key, req)).await?;
        let body = read_all(&mut stream).await?;
        Ok(api::parse_rpc(path, status, &body)?)
    }

    /// A map request; the responses arrive through [`MapStream::next`].
    pub async fn map(&self, req: &MapRequest) -> Result<MapStream, ControlError> {
        let (status, mut stream) = self.send(&Call::map(req)).await?;
        if status != 200 {
            let body = read_all(&mut stream).await.unwrap_or_default();
            return Err(api::failure("map request", status, &body).into());
        }
        Ok(MapStream {
            stream,
            frames: MapFrames::new(),
        })
    }
}

/// The frames of a map response, each read through [`MapFrames`] as it
/// arrives, never held whole.
pub struct MapStream {
    stream: h2::RecvStream,
    frames: MapFrames,
}

impl MapStream {
    /// The next data chunk, with its flow-control window handed back.
    async fn chunk(&mut self) -> Result<Option<Bytes>, ControlError> {
        match self.stream.data().await {
            Some(chunk) => {
                let chunk = chunk?;
                // Hand the window back, or a long stream stalls.
                let _ = self.stream.flow_control().release_capacity(chunk.len());
                Ok(Some(chunk))
            }
            None => Ok(None),
        }
    }

    /// Read and drop a response without parsing it. Returns whether there
    /// may be more.
    pub async fn skip(&mut self) -> Result<bool, ControlError> {
        self.frames = MapFrames::new();
        Ok(self.chunk().await?.is_some())
    }

    /// The next map response, or `None` when the server ends the stream.
    pub async fn next(&mut self) -> Result<Option<MapResponse>, ControlError> {
        loop {
            if let Some(response) = self.frames.pop() {
                return Ok(Some(response));
            }
            match self.chunk().await? {
                Some(chunk) => self.frames.feed(&chunk)?,
                None => {
                    self.frames.finish()?;
                    return Ok(None);
                }
            }
        }
    }
}

fn invalid(e: crate::control::noise::NoiseError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

async fn read_all(stream: &mut h2::RecvStream) -> Result<Vec<u8>, ControlError> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk?;
        let _ = stream.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
        if body.len() > MAX_MAP_FRAME {
            return Err(protocol("response too large"));
        }
    }
    Ok(body)
}

async fn server_key(base: &BaseUrl) -> Result<MachinePublic, ControlError> {
    let (status, body) = net::get(base, &api::key_path()).await?;
    Ok(api::parse_server_key(status, &body)?)
}

async fn read_more(io: &mut BoxIo, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.reserve(1024);
    if io.read_buf(buf).await? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// The Noise record layer ([`NoiseStream`]) as an async byte stream, for
/// the h2 crate.
struct NoiseIo {
    inner: BoxIo,
    noise: NoiseStream,
    /// Sealed bytes not yet written.
    pending: Vec<u8>,
    /// Where reads land (on the heap: small devices have small stacks).
    scratch: Box<[u8]>,
}

impl NoiseIo {
    fn new(inner: BoxIo, transport: Transport, leftover: Vec<u8>) -> io::Result<Self> {
        let mut noise = NoiseStream::new(transport, leftover);
        noise.decrypt().map_err(invalid)?;
        Ok(Self {
            inner,
            noise,
            pending: Vec::new(),
            scratch: vec![0; 4096].into_boxed_slice(),
        })
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NoiseIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.noise.readable() {
                let n = this.noise.read(out.initialize_unfilled());
                out.advance(n);
                return Poll::Ready(Ok(()));
            }
            let mut rb = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            this.noise
                .handle_input(&this.scratch[..n])
                .map_err(invalid)?;
        }
    }
}

impl AsyncWrite for NoiseIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Backpressure: finish the last write before taking more.
        ready!(this.poll_flush_pending(cx))?;
        let take = data.len().min(16 * 1024);
        this.noise.seal(&data[..take], &mut this.pending);
        // Start writing; whatever does not fit is flushed on the next call.
        let _ = this.poll_flush_pending(cx)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::noise::tests::server_respond;
    use crate::control::noise::EARLY_PAYLOAD_MAGIC;

    /// A connected client/server pair of Noise transports over a duplex pipe.
    fn pair() -> (NoiseIo, Transport, tokio::io::DuplexStream) {
        let machine = PrivateKey::generate();
        let control = PrivateKey::generate();
        let (client, init) =
            ClientHandshake::start(&machine, &MachinePublic(control.public()), 142).unwrap();
        let (server, resp, _) = server_respond(&control, &init);
        let client = client.finish(&resp).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        (
            NoiseIo::new(Box::new(a), client, Vec::new()).unwrap(),
            server,
            b,
        )
    }

    async fn server_send(
        server: &mut Transport,
        wire: &mut tokio::io::DuplexStream,
        records: &[&[u8]],
    ) {
        for r in records {
            let mut out = Vec::new();
            server.seal(r, &mut out);
            wire.write_all(&out).await.unwrap();
        }
    }

    #[tokio::test]
    async fn early_payload_split_across_records_is_dropped() {
        let (mut client, mut server, mut wire) = pair();
        let json = br#"{"nodeKeyChallenge":"chalpub:00"}"#;
        let mut early = EARLY_PAYLOAD_MAGIC.to_vec();
        early.extend_from_slice(&(json.len() as u32).to_be_bytes());
        early.extend_from_slice(json);
        let (a, b) = early.split_at(7);
        server_send(&mut server, &mut wire, &[a, b, b"PRI h2 bytes"]).await;
        let mut got = [0u8; 12];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"PRI h2 bytes");
    }

    #[tokio::test]
    async fn without_an_early_payload_nothing_is_lost() {
        let (mut client, mut server, mut wire) = pair();
        server_send(&mut server, &mut wire, &[b"abc", b"defghijk"]).await;
        let mut got = [0u8; 11];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abcdefghijk");
    }

    #[tokio::test]
    async fn writes_arrive_as_records() {
        let (mut client, mut server, mut wire) = pair();
        client.write_all(&vec![1u8; 20_000]).await.unwrap();
        client.flush().await.unwrap();
        let mut raw = Vec::new();
        let mut got = Vec::new();
        while got.len() < 20_000 {
            let mut chunk = [0u8; 8192];
            let n = wire.read(&mut chunk).await.unwrap();
            raw.extend_from_slice(&chunk[..n]);
            while let Some(r) = server.open(&mut raw).unwrap() {
                got.extend(r);
            }
        }
        assert_eq!(got, vec![1u8; 20_000]);
    }
}
