//! An HTTP/2 client (RFC 9113) without I/O, for one connection as control
//! uses it: client-initiated streams, no server push, priorities ignored.
//! Bytes from the server go in ([`Connection::handle_input`], in any
//! slicing: a frame may span many Noise records), bytes for the server
//! come out ([`Connection::poll_transmit`]), and what happened on the
//! streams is polled ([`Connection::poll_event`]).
//!
//! Flow control bounds memory: the server may send no more than the
//! windows we give, and the window is handed back only as the app
//! [`release`](Connection::release)s what it consumed.
//!
//! The tokio driver uses the `h2` crate; this one is for the drivers
//! without std, and is tested against `h2`.

mod hpack;
mod huffman_table;

use alloc::collections::{BTreeMap, VecDeque};

#[allow(unused_imports)]
use crate::prelude::*;

pub use hpack::{Header, HpackError};

/// What a client sends first (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// The window every stream and the connection start with (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: u32 = 65_535;
const MAX_WINDOW: i64 = (1 << 31) - 1;
/// The smallest SETTINGS_MAX_FRAME_SIZE there is, and what we accept.
const MIN_FRAME_SIZE: usize = 16_384;

/// Error codes (RFC 9113 §7).
pub mod code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum H2Error {
    /// We ended the connection (a GOAWAY with this code is queued).
    #[error("http/2: connection error {code:#x}: {reason}")]
    Connection { code: u32, reason: &'static str },
    /// The server sent GOAWAY, or the connection failed earlier.
    #[error("http/2: the connection is going away")]
    GoingAway,
    #[error("http/2: the server allows no more streams now")]
    TooManyStreams,
    #[error("http/2: no open stream {0}")]
    NoStream(u32),
}

fn connection_error(code: u32, reason: &'static str) -> H2Error {
    H2Error::Connection { code, reason }
}

/// How we run the connection.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Each stream's receive window: at most this much of a response is
    /// buffered in us ahead of the app's reading.
    pub stream_window: u32,
    /// The connection's receive window (all streams together).
    pub connection_window: u32,
    /// The HPACK dynamic table we allow the server.
    pub header_table_size: u32,
    /// The largest header list accepted.
    pub max_header_list: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stream_window: 64 << 10,
            connection_window: 64 << 10,
            header_table_size: 4096,
            max_header_list: 64 << 10,
        }
    }
}

/// A request's head: the pseudo-headers and the regular fields
/// (lowercase names).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
}

/// What happened, polled with [`Connection::poll_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A stream's response head (after any 1xx).
    Response {
        stream: u32,
        status: u16,
        headers: Vec<Header>,
    },
    /// Response body bytes: [`Connection::release`] them once consumed.
    Data { stream: u32, data: Vec<u8> },
    /// The response is complete.
    End { stream: u32 },
    /// The server reset the stream.
    Reset { stream: u32, code: u32 },
    /// The server is closing the connection: streams above `last_stream`
    /// were not processed (each also gets a [`Event::Reset`]).
    GoAway {
        last_stream: u32,
        code: u32,
        debug: Vec<u8>,
    },
}

struct Stream {
    /// What we may still send.
    send_window: i64,
    /// Body bytes waiting for window.
    pending: VecDeque<u8>,
    /// END_STREAM goes with the last pending byte.
    end_after_pending: bool,
    /// We sent END_STREAM.
    local_closed: bool,
    /// The server sent END_STREAM.
    remote_closed: bool,
    /// The response head arrived.
    responded: bool,
    /// What the server may still send.
    recv_window: i64,
    /// Bytes consumed and not yet handed back.
    unreleased: u32,
}

/// A header block arriving in HEADERS plus CONTINUATIONs.
struct Continuing {
    stream: u32,
    block: Vec<u8>,
    end_stream: bool,
}

/// See the module docs.
pub struct Connection {
    config: Config,
    out: Vec<u8>,
    /// Bytes of a frame not yet complete.
    input: Vec<u8>,
    decoder: hpack::Decoder,
    streams: BTreeMap<u32, Stream>,
    next_stream: u32,
    continuing: Option<Continuing>,
    events: VecDeque<Event>,
    /// The server's settings.
    peer_max_frame: usize,
    peer_initial_window: i64,
    peer_max_streams: u32,
    /// Connection-level windows.
    send_window: i64,
    recv_window: i64,
    unreleased: u32,
    /// The server's first frame must be SETTINGS.
    seen_settings: bool,
    /// GOAWAY received or sent: no new streams.
    going_away: bool,
    failed: Option<H2Error>,
}

impl Connection {
    /// A connection with the preface and our SETTINGS queued.
    pub fn new(config: Config) -> Self {
        let mut c = Self {
            config,
            out: Vec::new(),
            input: Vec::new(),
            decoder: hpack::Decoder::new(config.header_table_size as usize),
            streams: BTreeMap::new(),
            next_stream: 1,
            continuing: None,
            events: VecDeque::new(),
            peer_max_frame: MIN_FRAME_SIZE,
            peer_initial_window: i64::from(DEFAULT_WINDOW),
            peer_max_streams: u32::MAX,
            send_window: i64::from(DEFAULT_WINDOW),
            recv_window: i64::from(DEFAULT_WINDOW),
            unreleased: 0,
            seen_settings: false,
            going_away: false,
            failed: None,
        };
        c.out.extend_from_slice(PREFACE);
        let mut settings = Vec::new();
        for (id, value) in [
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_HEADER_TABLE_SIZE, config.header_table_size),
            (SETTINGS_INITIAL_WINDOW_SIZE, config.stream_window),
            (SETTINGS_MAX_FRAME_SIZE, MIN_FRAME_SIZE as u32),
            (SETTINGS_MAX_HEADER_LIST_SIZE, config.max_header_list),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&value.to_be_bytes());
        }
        c.frame(SETTINGS, 0, 0, &settings);
        // The connection window starts at 65535 whatever we set: widen it.
        let more = i64::from(config.connection_window) - i64::from(DEFAULT_WINDOW);
        if more > 0 {
            c.frame(WINDOW_UPDATE, 0, 0, &(more as u32).to_be_bytes());
            c.recv_window += more;
        }
        c
    }

    /// Open a stream with a request. The body follows as the windows allow, ending
    /// the stream unless `end` is false (then [`send_data`](Self::send_data)
    /// goes on).
    pub fn send_request(
        &mut self,
        request: &Request<'_>,
        body: &[u8],
        end: bool,
    ) -> Result<u32, H2Error> {
        self.check()?;
        if self.going_away {
            return Err(H2Error::GoingAway);
        }
        if self.streams.len() as u64 >= u64::from(self.peer_max_streams) {
            return Err(H2Error::TooManyStreams);
        }
        let id = self.next_stream;
        self.next_stream += 2;
        let mut fields = vec![
            (":method", request.method),
            (":scheme", request.scheme),
            (":authority", request.authority),
            (":path", request.path),
        ];
        fields.extend_from_slice(request.headers);
        let mut block = Vec::new();
        hpack::encode(&fields, &mut block);
        let only_headers = body.is_empty() && end;
        self.header_frames(id, &block, only_headers);
        self.streams.insert(
            id,
            Stream {
                send_window: self.peer_initial_window,
                pending: VecDeque::new(),
                end_after_pending: false,
                local_closed: only_headers,
                remote_closed: false,
                responded: false,
                recv_window: i64::from(self.config.stream_window),
                unreleased: 0,
            },
        );
        if !only_headers {
            self.send_data(id, body, end)?;
        }
        Ok(id)
    }

    /// More of a request body; `end` ends the stream.
    pub fn send_data(&mut self, stream: u32, data: &[u8], end: bool) -> Result<(), H2Error> {
        self.check()?;
        let s = self
            .streams
            .get_mut(&stream)
            .filter(|s| !s.local_closed && !s.end_after_pending)
            .ok_or(H2Error::NoStream(stream))?;
        s.pending.extend(data);
        s.end_after_pending = end;
        self.flush_stream(stream);
        Ok(())
    }

    /// Cancel a stream (RST_STREAM CANCEL); nothing more arrives for it.
    pub fn reset(&mut self, stream: u32) {
        if self.streams.remove(&stream).is_some() {
            self.frame(RST_STREAM, 0, stream, &code::CANCEL.to_be_bytes());
        }
    }

    /// The app consumed `n` bytes of `stream`'s body: hand the window back
    /// (once half of it is used, so updates stay few). Every
    /// [`Event::Data`] is released, also after its stream ended: the
    /// connection's window is shared.
    pub fn release(&mut self, stream: u32, n: usize) {
        self.release_connection(n);
        let n = n as u32;
        let half = self.config.stream_window / 2;
        let update = match self.streams.get_mut(&stream) {
            // A finished stream needs no window.
            Some(s) if !s.remote_closed => {
                s.unreleased += n;
                if s.unreleased >= half {
                    let n = core::mem::take(&mut s.unreleased);
                    s.recv_window += i64::from(n);
                    Some(n)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(n) = update {
            self.frame(WINDOW_UPDATE, 0, stream, &n.to_be_bytes());
        }
    }

    /// Say goodbye (GOAWAY NO_ERROR): no new streams.
    pub fn close(&mut self) {
        if !self.going_away {
            self.going_away = true;
            self.goaway(code::NO_ERROR);
        }
    }

    /// Bytes from the server, in any slicing.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), H2Error> {
        self.check()?;
        self.input.extend_from_slice(data);
        let mut at = 0;
        let result = loop {
            let rest = &self.input[at..];
            if rest.len() < 9 {
                break Ok(());
            }
            let len = usize::from(rest[0]) << 16 | usize::from(rest[1]) << 8 | usize::from(rest[2]);
            if len > MIN_FRAME_SIZE {
                break Err(connection_error(
                    code::FRAME_SIZE_ERROR,
                    "a frame over our maximum size",
                ));
            }
            if rest.len() < 9 + len {
                break Ok(());
            }
            let (kind, flags) = (rest[3], rest[4]);
            let stream = u32::from_be_bytes(rest[5..9].try_into().expect("4")) & 0x7fff_ffff;
            let payload = rest[9..9 + len].to_vec();
            at += 9 + len;
            if let Err(e) = self.on_frame(kind, flags, stream, payload) {
                break Err(e);
            }
        };
        self.input.drain(..at);
        if let Err(e) = &result {
            self.fail(e.clone());
        }
        result
    }

    /// The bytes to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        (!self.out.is_empty()).then(|| core::mem::take(&mut self.out))
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Whether a new stream can be opened.
    pub fn is_open(&self) -> bool {
        self.failed.is_none() && !self.going_away
    }

    /// The streams not yet finished.
    pub fn open_streams(&self) -> usize {
        self.streams.len()
    }

    // ------------------------------------------------------------ frames --

    fn on_frame(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    ) -> Result<(), H2Error> {
        if let Some(c) = &self.continuing {
            if kind != CONTINUATION || stream != c.stream {
                return Err(connection_error(
                    code::PROTOCOL_ERROR,
                    "a frame inside a header block",
                ));
            }
        }
        if !self.seen_settings && kind != SETTINGS {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "the server's first frame is not SETTINGS",
            ));
        }
        match kind {
            DATA => self.on_data(flags, stream, payload),
            HEADERS => self.on_headers(flags, stream, payload),
            CONTINUATION => self.on_continuation(flags, stream, payload),
            PRIORITY => {
                if stream == 0 || payload.len() != 5 {
                    return Err(connection_error(
                        code::PROTOCOL_ERROR,
                        "a bad PRIORITY frame",
                    ));
                }
                Ok(())
            }
            RST_STREAM => {
                if stream == 0 || payload.len() != 4 {
                    return Err(connection_error(
                        code::PROTOCOL_ERROR,
                        "a bad RST_STREAM frame",
                    ));
                }
                if self.streams.remove(&stream).is_some() {
                    let code = u32::from_be_bytes(payload[..4].try_into().expect("4"));
                    self.events.push_back(Event::Reset { stream, code });
                }
                Ok(())
            }
            SETTINGS => self.on_settings(flags, stream, &payload),
            PUSH_PROMISE => Err(connection_error(
                code::PROTOCOL_ERROR,
                "PUSH_PROMISE with push off",
            )),
            PING => {
                if stream != 0 || payload.len() != 8 {
                    return Err(connection_error(code::FRAME_SIZE_ERROR, "a bad PING frame"));
                }
                if flags & ACK == 0 {
                    self.frame(PING, ACK, 0, &payload);
                }
                Ok(())
            }
            GOAWAY => {
                if stream != 0 || payload.len() < 8 {
                    return Err(connection_error(code::PROTOCOL_ERROR, "a bad GOAWAY frame"));
                }
                let last_stream =
                    u32::from_be_bytes(payload[..4].try_into().expect("4")) & 0x7fff_ffff;
                let code = u32::from_be_bytes(payload[4..8].try_into().expect("4"));
                self.going_away = true;
                self.events.push_back(Event::GoAway {
                    last_stream,
                    code,
                    debug: payload[8..].to_vec(),
                });
                let unprocessed: Vec<u32> = self
                    .streams
                    .range(last_stream + 1..)
                    .map(|(id, _)| *id)
                    .collect();
                for stream in unprocessed {
                    self.streams.remove(&stream);
                    self.events.push_back(Event::Reset {
                        stream,
                        code: code::REFUSED_STREAM,
                    });
                }
                Ok(())
            }
            WINDOW_UPDATE => self.on_window_update(stream, &payload),
            // Unknown frame types are ignored (RFC 9113 §4.1).
            _ => Ok(()),
        }
    }

    fn on_settings(&mut self, flags: u8, stream: u32, payload: &[u8]) -> Result<(), H2Error> {
        if stream != 0 {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "SETTINGS on a stream",
            ));
        }
        if flags & ACK != 0 {
            if !payload.is_empty() {
                return Err(connection_error(
                    code::FRAME_SIZE_ERROR,
                    "a SETTINGS ack with a payload",
                ));
            }
            return Ok(());
        }
        if !payload.len().is_multiple_of(6) {
            return Err(connection_error(
                code::FRAME_SIZE_ERROR,
                "a SETTINGS frame of a bad length",
            ));
        }
        self.seen_settings = true;
        for setting in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([setting[0], setting[1]]);
            let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
            match id {
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if i64::from(value) > MAX_WINDOW {
                        return Err(connection_error(
                            code::FLOW_CONTROL_ERROR,
                            "an initial window over 2^31-1",
                        ));
                    }
                    // Every stream's send window moves by the difference.
                    let delta = i64::from(value) - self.peer_initial_window;
                    self.peer_initial_window = i64::from(value);
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                        if s.send_window > MAX_WINDOW {
                            return Err(connection_error(
                                code::FLOW_CONTROL_ERROR,
                                "a stream window over 2^31-1",
                            ));
                        }
                    }
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(MIN_FRAME_SIZE as u32..=(1 << 24) - 1).contains(&value) {
                        return Err(connection_error(
                            code::PROTOCOL_ERROR,
                            "a bad SETTINGS_MAX_FRAME_SIZE",
                        ));
                    }
                    self.peer_max_frame = value as usize;
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => self.peer_max_streams = value,
                SETTINGS_ENABLE_PUSH if value > 1 => {
                    return Err(connection_error(
                        code::PROTOCOL_ERROR,
                        "a bad SETTINGS_ENABLE_PUSH",
                    ));
                }
                // The server's decoder table: our encoder indexes nothing,
                // so its size does not matter. Others are ignored.
                _ => {}
            }
        }
        self.frame(SETTINGS, ACK, 0, &[]);
        self.flush_all();
        Ok(())
    }

    fn on_window_update(&mut self, stream: u32, payload: &[u8]) -> Result<(), H2Error> {
        if payload.len() != 4 {
            return Err(connection_error(
                code::FRAME_SIZE_ERROR,
                "a bad WINDOW_UPDATE frame",
            ));
        }
        let n = i64::from(u32::from_be_bytes(payload.try_into().expect("4")) & 0x7fff_ffff);
        if stream == 0 {
            if n == 0 {
                return Err(connection_error(
                    code::PROTOCOL_ERROR,
                    "a WINDOW_UPDATE of 0",
                ));
            }
            self.send_window += n;
            if self.send_window > MAX_WINDOW {
                return Err(connection_error(
                    code::FLOW_CONTROL_ERROR,
                    "the connection window over 2^31-1",
                ));
            }
            self.flush_all();
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            // For a stream already closed: ignored.
            return Ok(());
        };
        if n == 0 {
            self.streams.remove(&stream);
            self.frame(RST_STREAM, 0, stream, &code::PROTOCOL_ERROR.to_be_bytes());
            self.events.push_back(Event::Reset {
                stream,
                code: code::PROTOCOL_ERROR,
            });
            return Ok(());
        }
        s.send_window += n;
        if s.send_window > MAX_WINDOW {
            self.streams.remove(&stream);
            self.frame(
                RST_STREAM,
                0,
                stream,
                &code::FLOW_CONTROL_ERROR.to_be_bytes(),
            );
            self.events.push_back(Event::Reset {
                stream,
                code: code::FLOW_CONTROL_ERROR,
            });
            return Ok(());
        }
        self.flush_stream(stream);
        Ok(())
    }

    fn on_data(&mut self, flags: u8, stream: u32, payload: Vec<u8>) -> Result<(), H2Error> {
        if stream == 0 {
            return Err(connection_error(code::PROTOCOL_ERROR, "DATA on stream 0"));
        }
        // All of it counts against the windows, padding too.
        let len = payload.len();
        self.recv_window -= len as i64;
        if self.recv_window < 0 {
            return Err(connection_error(
                code::FLOW_CONTROL_ERROR,
                "DATA over the connection window",
            ));
        }
        let data = unpad(flags, payload)?;
        let padding = len - data.len();
        let known = stream < self.next_stream;
        let Some(s) = self.streams.get_mut(&stream) else {
            if !known {
                return Err(connection_error(
                    code::PROTOCOL_ERROR,
                    "DATA on a stream never opened",
                ));
            }
            // A stream we reset or finished: hand the window back.
            self.release_connection(len);
            return Ok(());
        };
        if s.remote_closed || !s.responded {
            self.streams.remove(&stream);
            self.frame(RST_STREAM, 0, stream, &code::STREAM_CLOSED.to_be_bytes());
            self.events.push_back(Event::Reset {
                stream,
                code: code::STREAM_CLOSED,
            });
            self.release_connection(len);
            return Ok(());
        }
        s.recv_window -= len as i64;
        if s.recv_window < 0 {
            self.streams.remove(&stream);
            self.frame(
                RST_STREAM,
                0,
                stream,
                &code::FLOW_CONTROL_ERROR.to_be_bytes(),
            );
            self.events.push_back(Event::Reset {
                stream,
                code: code::FLOW_CONTROL_ERROR,
            });
            self.release_connection(len);
            return Ok(());
        }
        // Padding is consumed at once; the data when the app says so.
        if padding > 0 {
            self.release(stream, padding);
        }
        if !data.is_empty() {
            self.events.push_back(Event::Data { stream, data });
        }
        if flags & END_STREAM != 0 {
            self.remote_end(stream);
        }
        Ok(())
    }

    fn on_headers(&mut self, flags: u8, stream: u32, payload: Vec<u8>) -> Result<(), H2Error> {
        if stream == 0 {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "HEADERS on stream 0",
            ));
        }
        let mut block = unpad(flags, payload)?;
        if flags & PRIORITY_FLAG != 0 {
            if block.len() < 5 {
                return Err(connection_error(
                    code::PROTOCOL_ERROR,
                    "a short HEADERS priority",
                ));
            }
            block.drain(..5);
        }
        let end_stream = flags & END_STREAM != 0;
        if flags & END_HEADERS != 0 {
            self.on_header_block(stream, &block, end_stream)
        } else {
            self.continuing = Some(Continuing {
                stream,
                block,
                end_stream,
            });
            Ok(())
        }
    }

    fn on_continuation(&mut self, flags: u8, stream: u32, payload: Vec<u8>) -> Result<(), H2Error> {
        let Some(c) = self.continuing.as_mut() else {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "CONTINUATION without HEADERS",
            ));
        };
        c.block.extend_from_slice(&payload);
        if c.block.len() > self.config.max_header_list as usize * 2 {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "a header block too large",
            ));
        }
        if flags & END_HEADERS != 0 {
            let c = self.continuing.take().expect("continuing");
            debug_assert_eq!(c.stream, stream);
            self.on_header_block(c.stream, &c.block, c.end_stream)
        } else {
            Ok(())
        }
    }

    fn on_header_block(
        &mut self,
        stream: u32,
        block: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        // Decoded whatever the stream: the table is the connection's.
        let headers = self
            .decoder
            .decode(block, self.config.max_header_list as usize)
            .map_err(|e| {
                tracing::debug!("http/2: {e}");
                connection_error(code::COMPRESSION_ERROR, "a bad header block")
            })?;
        if stream >= self.next_stream || stream.is_multiple_of(2) {
            return Err(connection_error(
                code::PROTOCOL_ERROR,
                "HEADERS on a stream we did not open",
            ));
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            // A stream we reset: nothing to tell.
            return Ok(());
        };
        if s.remote_closed {
            return Err(connection_error(
                code::STREAM_CLOSED,
                "HEADERS after the end of a stream",
            ));
        }
        if !s.responded {
            let status = headers
                .iter()
                .find(|(n, _)| n == b":status")
                .and_then(|(_, v)| core::str::from_utf8(v).ok())
                .and_then(|v| v.parse::<u16>().ok());
            let Some(status) = status else {
                self.streams.remove(&stream);
                self.frame(RST_STREAM, 0, stream, &code::PROTOCOL_ERROR.to_be_bytes());
                self.events.push_back(Event::Reset {
                    stream,
                    code: code::PROTOCOL_ERROR,
                });
                return Ok(());
            };
            // Informational: the final response follows.
            if (100..200).contains(&status) {
                return Ok(());
            }
            s.responded = true;
            let headers = headers
                .into_iter()
                .filter(|(n, _)| !n.starts_with(b":"))
                .collect();
            self.events.push_back(Event::Response {
                stream,
                status,
                headers,
            });
        }
        // Trailers (a later block) are dropped: control sends none we use.
        if end_stream {
            self.remote_end(stream);
        }
        Ok(())
    }

    // ----------------------------------------------------------- helpers --

    fn remote_end(&mut self, stream: u32) {
        let Some(s) = self.streams.get_mut(&stream) else {
            return;
        };
        s.remote_closed = true;
        self.events.push_back(Event::End { stream });
        // A response that ends before our request does: the rest of the
        // request is not wanted (RFC 9113 §8.1).
        if !s.local_closed {
            self.frame(RST_STREAM, 0, stream, &code::NO_ERROR.to_be_bytes());
        }
        self.streams.remove(&stream);
    }

    fn release_connection(&mut self, n: usize) {
        self.unreleased += n as u32;
        if self.unreleased >= self.config.connection_window / 2 {
            let n = core::mem::take(&mut self.unreleased);
            self.recv_window += i64::from(n);
            self.frame(WINDOW_UPDATE, 0, 0, &n.to_be_bytes());
        }
    }

    /// Send what the windows allow of every stream's pending body.
    fn flush_all(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.flush_stream(id);
        }
    }

    fn flush_stream(&mut self, id: u32) {
        loop {
            let max = self.peer_max_frame;
            let window = self.send_window;
            let Some(s) = self.streams.get_mut(&id) else {
                return;
            };
            if s.local_closed {
                return;
            }
            let n = s
                .pending
                .len()
                .min(max)
                .min(window.max(0) as usize)
                .min(s.send_window.max(0) as usize);
            let last = n == s.pending.len();
            if n == 0 && !(last && s.end_after_pending) {
                return;
            }
            let chunk: Vec<u8> = s.pending.drain(..n).collect();
            s.send_window -= n as i64;
            let end = last && s.end_after_pending;
            if end {
                s.local_closed = true;
            }
            self.send_window -= n as i64;
            self.frame(DATA, if end { END_STREAM } else { 0 }, id, &chunk);
            if last {
                return;
            }
        }
    }

    fn header_frames(&mut self, stream: u32, block: &[u8], end_stream: bool) {
        let max = self.peer_max_frame;
        let mut chunks = block.chunks(max).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let mut flags = if end_stream { END_STREAM } else { 0 };
        if chunks.peek().is_none() {
            flags |= END_HEADERS;
        }
        self.frame(HEADERS, flags, stream, first);
        while let Some(chunk) = chunks.next() {
            let flags = if chunks.peek().is_none() {
                END_HEADERS
            } else {
                0
            };
            self.frame(CONTINUATION, flags, stream, chunk);
        }
    }

    fn frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        self.out.extend_from_slice(&len.to_be_bytes()[1..]);
        self.out.push(kind);
        self.out.push(flags);
        self.out.extend_from_slice(&stream.to_be_bytes());
        self.out.extend_from_slice(payload);
    }

    fn goaway(&mut self, code: u32) {
        // We accept no streams of the server's: the last is 0.
        let mut payload = [0u8; 8];
        payload[4..].copy_from_slice(&code.to_be_bytes());
        self.frame(GOAWAY, 0, 0, &payload);
    }

    fn fail(&mut self, e: H2Error) {
        if self.failed.is_some() {
            return;
        }
        if let H2Error::Connection { code, .. } = e {
            self.goaway(code);
        }
        self.going_away = true;
        self.failed = Some(e);
    }

    fn check(&self) -> Result<(), H2Error> {
        match &self.failed {
            Some(_) => Err(H2Error::GoingAway),
            None => Ok(()),
        }
    }
}

/// A payload without its padding (PADDED: a length byte, then padding).
fn unpad(flags: u8, mut payload: Vec<u8>) -> Result<Vec<u8>, H2Error> {
    if flags & PADDED == 0 {
        return Ok(payload);
    }
    let pad = usize::from(*payload.first().ok_or_else(|| {
        connection_error(code::PROTOCOL_ERROR, "a padded frame without its length")
    })?);
    if pad + 1 > payload.len() {
        return Err(connection_error(
            code::PROTOCOL_ERROR,
            "padding longer than the frame",
        ));
    }
    payload.truncate(payload.len() - pad);
    payload.remove(0);
    Ok(payload)
}

#[cfg(test)]
mod tests;
