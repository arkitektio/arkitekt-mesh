//! A control connection without I/O, for the drivers without std: the
//! ts2021 upgrade, Noise, then [`Call`]s over our own HTTP/2
//! ([`crate::http2`]), on one byte stream (TLS or plain TCP, the driver's).
//!
//! The server's Noise key comes first, from `GET /key` on a connection of
//! its own ([`super::api::key_path`], [`super::http1`]).

use alloc::collections::{BTreeMap, VecDeque};

#[allow(unused_imports)]
use crate::prelude::*;

use super::api::{failure, ApiError, Call, MapFrames, MAX_RESPONSE};
use super::http1::{self, Http1Error};
use super::noise::{ClientHandshake, NoiseError, NoiseStream, MAX_MESSAGE, RESPONSE_LEN};
use super::types::{MapResponse, CAPABILITY_VERSION};
use crate::http2::{self, H2Error, Request};
use crate::keys::{MachinePublic, PrivateKey};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnError {
    #[error("control: {0}")]
    Http1(#[from] Http1Error),
    #[error("control: the upgrade to ts2021 failed with HTTP {0}")]
    Upgrade(u16),
    #[error("control: {0}")]
    Noise(#[from] NoiseError),
    #[error("control: {0}")]
    H2(#[from] H2Error),
}

/// A request on the connection (its HTTP/2 stream).
pub type CallId = u32;

/// What happened, polled with [`ControlConn::poll_event`].
#[derive(Debug, Clone)]
pub enum Event {
    /// Noise is up: calls may go out.
    Ready,
    /// A [`ControlConn::call`]'s answer, whole.
    Answer {
        id: CallId,
        status: u16,
        body: Vec<u8>,
    },
    /// One response on a [`ControlConn::map`] stream.
    Map {
        id: CallId,
        response: Box<MapResponse>,
    },
    /// The map stream ended (the server closed it).
    MapEnded { id: CallId },
    /// A call failed: refused, reset, or a bad answer.
    Failed { id: CallId, error: ApiError },
    /// The server is closing the connection: open a new one.
    GoingAway,
}

enum Phase {
    /// The upgrade request is out; the 101 and the handshake response are
    /// read into `buf`.
    Upgrading {
        handshake: Option<ClientHandshake>,
        buf: Vec<u8>,
    },
    Open {
        noise: NoiseStream,
        h2: Box<http2::Connection>,
    },
    Failed,
}

enum Answer {
    /// A whole body, read to its end.
    Whole { status: u16, body: Vec<u8> },
    /// A map stream.
    Map {
        status: u16,
        frames: Box<MapFrames>,
        error_body: Vec<u8>,
    },
}

/// See the module docs.
pub struct ControlConn {
    authority: String,
    config: http2::Config,
    phase: Phase,
    out: Vec<u8>,
    calls: BTreeMap<CallId, Answer>,
    events: VecDeque<Event>,
}

impl ControlConn {
    /// A connection to the server at `authority` (its Host), whose Noise
    /// key is `server_key`; the upgrade request is queued.
    pub fn new(
        authority: &str,
        machine: &PrivateKey,
        server_key: &MachinePublic,
        config: http2::Config,
    ) -> Result<Self, ConnError> {
        let (handshake, init) = ClientHandshake::start(machine, server_key, CAPABILITY_VERSION)?;
        Ok(Self {
            authority: authority.to_owned(),
            config,
            phase: Phase::Upgrading {
                handshake: Some(handshake),
                buf: Vec::new(),
            },
            out: super::api::upgrade_request(authority, &init),
            calls: BTreeMap::new(),
            events: VecDeque::new(),
        })
    }

    /// Whether calls may go out.
    pub fn is_ready(&self) -> bool {
        matches!(&self.phase, Phase::Open { h2, .. } if h2.is_open())
    }

    /// A call answered whole ([`Event::Answer`]).
    pub fn call(&mut self, call: &Call) -> Result<CallId, ConnError> {
        let id = self.send(call)?;
        self.calls.insert(
            id,
            Answer::Whole {
                status: 0,
                body: Vec::new(),
            },
        );
        Ok(id)
    }

    /// A map request, its responses arriving one by one ([`Event::Map`]).
    pub fn map(&mut self, call: &Call) -> Result<CallId, ConnError> {
        let id = self.send(call)?;
        self.calls.insert(
            id,
            Answer::Map {
                status: 0,
                frames: Box::default(),
                error_body: Vec::new(),
            },
        );
        Ok(id)
    }

    /// Stop a call (the map stream, typically).
    pub fn cancel(&mut self, id: CallId) {
        if let Phase::Open { h2, .. } = &mut self.phase {
            h2.reset(id);
            self.calls.remove(&id);
            self.flush();
        }
    }

    /// Bytes from the server, in any slicing.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), ConnError> {
        let result = self.input(data);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        self.flush();
        result
    }

    /// The bytes to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        (!self.out.is_empty()).then(|| core::mem::take(&mut self.out))
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // ----------------------------------------------------------- inside --

    fn send(&mut self, call: &Call) -> Result<CallId, ConnError> {
        let Phase::Open { h2, .. } = &mut self.phase else {
            return Err(ConnError::H2(H2Error::GoingAway));
        };
        let headers = call.headers();
        let path = call.path.as_str();
        let request = Request {
            method: call.method,
            scheme: "https",
            authority: &self.authority,
            path,
            headers: &headers,
        };
        let id = h2.send_request(&request, &call.body, true)?;
        self.flush();
        Ok(id)
    }

    fn input(&mut self, data: &[u8]) -> Result<(), ConnError> {
        match &mut self.phase {
            Phase::Failed => Err(ConnError::H2(H2Error::GoingAway)),
            Phase::Upgrading { handshake, buf } => {
                buf.extend_from_slice(data);
                let Some((head, used)) = http1::parse_head(buf)? else {
                    return Ok(());
                };
                if head.status != 101 {
                    return Err(ConnError::Upgrade(head.status));
                }
                // The server corks its answer: the response may ride with the head.
                let rest = &buf[used..];
                if rest.len() < 3 {
                    return Ok(());
                }
                let want = ClientHandshake::response_len(&rest[..3].try_into().expect("3"));
                if want > MAX_MESSAGE {
                    return Err(ConnError::Noise(NoiseError::Malformed));
                }
                if rest.len() < want {
                    return Ok(());
                }
                let transport = handshake.take().expect("handshake").finish(&rest[..want])?;
                if want != RESPONSE_LEN {
                    return Err(ConnError::Noise(NoiseError::Malformed));
                }
                let leftover = rest[want..].to_vec();
                let mut noise = NoiseStream::new(transport, leftover);
                noise.decrypt()?;
                self.phase = Phase::Open {
                    noise,
                    h2: Box::new(http2::Connection::new(self.config)),
                };
                self.events.push_back(Event::Ready);
                self.pump()
            }
            Phase::Open { noise, .. } => {
                noise.handle_input(data)?;
                self.pump()
            }
        }
    }

    /// Plaintext into HTTP/2, its events into ours.
    fn pump(&mut self) -> Result<(), ConnError> {
        let Phase::Open { noise, h2 } = &mut self.phase else {
            return Ok(());
        };
        let plain = noise.take();
        if !plain.is_empty() {
            h2.handle_input(&plain)?;
        }
        while let Some(event) = h2.poll_event() {
            match event {
                http2::Event::Response { stream, status, .. } => {
                    match self.calls.get_mut(&stream) {
                        Some(Answer::Whole { status: s, .. } | Answer::Map { status: s, .. }) => {
                            *s = status
                        }
                        None => {}
                    }
                }
                http2::Event::Data { stream, data } => {
                    let failed = match self.calls.get_mut(&stream) {
                        Some(Answer::Whole { body, .. }) => {
                            body.extend_from_slice(&data);
                            (body.len() > MAX_RESPONSE)
                                .then(|| ApiError("response too large".into()))
                        }
                        Some(Answer::Map {
                            status: 200,
                            frames,
                            ..
                        }) => match frames.feed(&data) {
                            Ok(()) => {
                                while let Some(response) = frames.pop() {
                                    self.events.push_back(Event::Map {
                                        id: stream,
                                        response: Box::new(response),
                                    });
                                }
                                None
                            }
                            Err(e) => Some(e),
                        },
                        Some(Answer::Map { error_body, .. }) => {
                            // A refusal's text, capped.
                            let room = 4096usize.saturating_sub(error_body.len());
                            error_body.extend_from_slice(&data[..data.len().min(room)]);
                            None
                        }
                        None => None,
                    };
                    // Consumed: the window goes back.
                    h2.release(stream, data.len());
                    if let Some(error) = failed {
                        self.calls.remove(&stream);
                        h2.reset(stream);
                        self.events.push_back(Event::Failed { id: stream, error });
                    }
                }
                http2::Event::End { stream } => {
                    let event = match self.calls.remove(&stream) {
                        Some(Answer::Whole { status, body }) => Event::Answer {
                            id: stream,
                            status,
                            body,
                        },
                        Some(Answer::Map {
                            status: 200,
                            frames,
                            ..
                        }) => match frames.finish() {
                            Ok(()) => Event::MapEnded { id: stream },
                            Err(error) => Event::Failed { id: stream, error },
                        },
                        Some(Answer::Map {
                            status, error_body, ..
                        }) => Event::Failed {
                            id: stream,
                            error: failure("map request", status, &error_body),
                        },
                        None => continue,
                    };
                    self.events.push_back(event);
                }
                http2::Event::Reset { stream, code } => {
                    if self.calls.remove(&stream).is_some() {
                        self.events.push_back(Event::Failed {
                            id: stream,
                            error: ApiError(format!(
                                "control: the server reset the request ({code:#x})"
                            )),
                        });
                    }
                }
                http2::Event::GoAway { .. } => self.events.push_back(Event::GoingAway),
            }
        }
        Ok(())
    }

    /// HTTP/2's output, sealed.
    fn flush(&mut self) {
        if let Phase::Open { noise, h2 } = &mut self.phase {
            if let Some(plain) = h2.poll_transmit() {
                noise.seal(&plain, &mut self.out);
            }
        }
    }
}
