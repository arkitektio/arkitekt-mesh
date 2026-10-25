//! The control protocol's requests and answers, whatever carries them:
//! the tokio driver sends them over the `h2` crate, the drivers without std
//! over [`super::conn::ControlConn`]. A request is a [`Call`]; its answer
//! is parsed from status and body, a map stream's body through
//! [`MapFrames`] as it arrives.

use alloc::collections::VecDeque;

#[allow(unused_imports)]
use crate::prelude::*;

use super::stream::{MapReader, StreamError};
use super::types::{
    MapRequest, MapResponse, RegisterRequest, RegisterResponse, ServerKeys, CAPABILITY_VERSION,
};
use crate::keys::{MachinePublic, NodePublic};

/// The largest map response frame accepted.
pub const MAX_MAP_FRAME: usize = 16 << 20;
/// The largest body of any other answer.
pub const MAX_RESPONSE: usize = 10 << 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ApiError(pub String);

fn error(msg: impl Into<String>) -> ApiError {
    ApiError(msg.into())
}

/// Where the server's Noise key is asked for (plain HTTP(S), before Noise).
pub fn key_path() -> String {
    format!("/key?v={CAPABILITY_VERSION}")
}

pub fn parse_server_key(status: u16, body: &[u8]) -> Result<MachinePublic, ApiError> {
    if status != 200 {
        return Err(error(format!("GET /key failed with HTTP {status}")));
    }
    let keys: ServerKeys =
        serde_json::from_slice(body).map_err(|e| error(format!("bad /key response: {e}")))?;
    Ok(keys.public_key)
}

/// The ts2021 upgrade request carrying the Noise initiation.
pub fn upgrade_request(authority: &str, initiation: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let handshake = base64::engine::general_purpose::STANDARD.encode(initiation);
    super::http1::request(
        "POST",
        "/ts2021",
        authority,
        &[
            "Upgrade: tailscale-control-protocol",
            "Connection: upgrade",
            &format!("X-Tailscale-Handshake: {handshake}"),
            "Content-Length: 0",
        ],
    )
}

/// The path of the WebSocket form of the upgrade (`GET`, the
/// `tailscale-control-protocol` subprotocol): the initiation goes in the
/// query, where a browser can put it.
pub fn websocket_path(initiation: &[u8]) -> String {
    use base64::Engine;
    let handshake = base64::engine::general_purpose::STANDARD.encode(initiation);
    let mut path = String::from("/ts2021?X-Tailscale-Handshake=");
    for c in handshake.chars() {
        match c {
            '+' => path.push_str("%2B"),
            '/' => path.push_str("%2F"),
            '=' => path.push_str("%3D"),
            c => path.push(c),
        }
    }
    path
}

/// The subprotocol the WebSocket form asks for.
pub const WEBSOCKET_PROTOCOL: &str = "tailscale-control-protocol";

/// One request to control, over the Noise connection's HTTP/2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub method: &'static str,
    pub path: String,
    /// The node the request is for (the `ts-lb` header).
    pub node_key: String,
    pub body: Vec<u8>,
}

impl Call {
    pub fn register(req: &RegisterRequest) -> Self {
        Self::json("POST", "/machine/register", &req.node_key, req)
    }

    /// A map request; the answer is a stream read through [`MapFrames`].
    pub fn map(req: &MapRequest) -> Self {
        Self::json("POST", "/machine/map", &req.node_key, req)
    }

    /// A JSON RPC in Go's style: a GET with a JSON body (the tailnet-lock
    /// endpoints under `/machine/tka/`).
    pub fn rpc<Req: serde::Serialize>(path: &str, node_key: &NodePublic, req: &Req) -> Self {
        Self::json("GET", path, node_key, req)
    }

    fn json<T: serde::Serialize>(
        method: &'static str,
        path: &str,
        node_key: &NodePublic,
        body: &T,
    ) -> Self {
        Self {
            method,
            path: path.to_owned(),
            node_key: node_key.text(),
            // Our own types always serialize.
            body: serde_json::to_vec(body).expect("serializable"),
        }
    }

    /// The regular header fields to send with it.
    pub fn headers(&self) -> [(&str, &str); 2] {
        [
            ("content-type", "application/json"),
            ("ts-lb", &self.node_key),
        ]
    }
}

/// A failed answer's error, with what the server said.
pub fn failure(what: &str, status: u16, body: &[u8]) -> ApiError {
    error(format!(
        "{what} failed with HTTP {status}: {}",
        String::from_utf8_lossy(body).trim()
    ))
}

pub fn parse_register(status: u16, body: &[u8]) -> Result<RegisterResponse, ApiError> {
    if status != 200 {
        return Err(failure("register", status, body));
    }
    serde_json::from_slice(body).map_err(|e| error(format!("bad register response: {e}")))
}

pub fn parse_rpc<Resp: serde::de::DeserializeOwned>(
    path: &str,
    status: u16,
    body: &[u8],
) -> Result<Resp, ApiError> {
    if status != 200 {
        return Err(failure(path, status, body));
    }
    if body.len() > MAX_RESPONSE {
        return Err(error(format!("{path}: response too large")));
    }
    serde_json::from_slice(body).map_err(|e| error(format!("bad {path} response: {e}")))
}

/// A map stream's body, `u32 LE length ‖ JSON` frames, read as it
/// arrives: each frame through a [`MapReader`], never held whole.
#[derive(Default)]
pub struct MapFrames {
    /// The length prefix read so far.
    prefix: Vec<u8>,
    /// The frame being read and how much of it is left.
    frame: Option<(MapReader, usize)>,
    ready: VecDeque<MapResponse>,
}

impl MapFrames {
    pub fn new() -> Self {
        Self::default()
    }

    /// Body bytes, in any slicing.
    pub fn feed(&mut self, mut data: &[u8]) -> Result<(), ApiError> {
        let bad = |e: StreamError| error(e.to_string());
        while !data.is_empty() {
            match &mut self.frame {
                None => {
                    let take = (4 - self.prefix.len()).min(data.len());
                    self.prefix.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if self.prefix.len() == 4 {
                        let len =
                            u32::from_le_bytes(self.prefix[..].try_into().expect("4")) as usize;
                        self.prefix.clear();
                        if len == 0 || len > MAX_MAP_FRAME {
                            return Err(error(format!("bad map frame length {len}")));
                        }
                        self.frame = Some((MapReader::new(), len));
                    }
                }
                Some((reader, left)) => {
                    let take = (*left).min(data.len());
                    reader.feed(&data[..take]).map_err(bad)?;
                    data = &data[take..];
                    *left -= take;
                    if *left == 0 {
                        let (reader, _) = self.frame.take().expect("frame");
                        self.ready.push_back(reader.finish().map_err(bad)?);
                    }
                }
            }
        }
        Ok(())
    }

    /// A complete map response, if one is.
    pub fn pop(&mut self) -> Option<MapResponse> {
        self.ready.pop_front()
    }

    /// The stream ended: it must not have ended inside a frame.
    pub fn finish(&self) -> Result<(), ApiError> {
        if self.frame.is_some() || !self.prefix.is_empty() {
            return Err(error("the map stream ended mid-frame"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(json: &str) -> Vec<u8> {
        let mut f = (json.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(json.as_bytes());
        f
    }

    #[test]
    fn map_frames_in_any_slicing() {
        let mut stream = frame(r#"{"KeepAlive":true}"#);
        stream.extend(frame(r#"{"Domain":"tail.example","Peers":[]}"#));
        for slice in [1, 3, 7, stream.len()] {
            let mut frames = MapFrames::new();
            let mut got = Vec::new();
            for chunk in stream.chunks(slice) {
                frames.feed(chunk).unwrap();
                got.extend(core::iter::from_fn(|| frames.pop()));
            }
            frames.finish().unwrap();
            assert_eq!(got.len(), 2);
            assert!(got[0].keep_alive);
            assert_eq!(got[1].domain, "tail.example");
        }
    }

    #[test]
    fn bad_and_cut_frames() {
        let mut frames = MapFrames::new();
        assert!(frames.feed(&0u32.to_le_bytes()).is_err());
        let mut frames = MapFrames::new();
        assert!(frames
            .feed(&((MAX_MAP_FRAME + 1) as u32).to_le_bytes())
            .is_err());
        let mut frames = MapFrames::new();
        frames.feed(&frame(r#"{"KeepAlive":true}"#)[..6]).unwrap();
        assert!(frames.finish().is_err());
    }

    #[test]
    fn the_websocket_path_escapes_base64() {
        // 0xfb 0xff 0xfe encodes to "+//+": every character escaped.
        assert_eq!(
            websocket_path(&[0xfb, 0xff, 0xfe]),
            "/ts2021?X-Tailscale-Handshake=%2B%2F%2F%2B"
        );
        assert!(websocket_path(&[1]).ends_with("AQ%3D%3D"));
    }

    #[test]
    fn the_upgrade_carries_the_initiation() {
        let r = String::from_utf8(upgrade_request("c.example:443", &[1, 2, 3])).unwrap();
        assert!(r.starts_with("POST /ts2021 HTTP/1.1\r\nHost: c.example:443\r\n"));
        assert!(r.contains("\r\nX-Tailscale-Handshake: AQID\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
    }
}
