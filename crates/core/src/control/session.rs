//! The control loop's policy without I/O: when to connect, register,
//! open the map stream and send updates, what a refusal means, when the
//! stream is dead and how long to wait before trying again.
//!
//! The session asks for a connection ([`Event::Connect`]) and for calls
//! ([`Event::Send`]), each by its own [`CallId`]; the driver makes them
//! over its transport (the `h2` crate on tokio, [`super::conn::ControlConn`]
//! elsewhere) and reports back ([`ControlSession::connected`],
//! [`ControlSession::answer`], [`ControlSession::disconnected`]).
//! Map responses come out as [`Event::Map`], tailnet-lock info included:
//! the driver syncs the lock before it applies one.

use alloc::collections::VecDeque;
use core::net::SocketAddr;

#[allow(unused_imports)]
use crate::prelude::*;

use super::api::{self, ApiError, Call};
use super::types::{
    EndpointType, Hostinfo, MapRequest, MapResponse, NetInfo, RegisterAuth, RegisterRequest,
    CAPABILITY_VERSION,
};
use crate::keys::{DiscoPublic, NodePublic};
use crate::node::HomeReport;
use crate::time::{Duration, Instant};

/// Control sends a keepalive every minute; a map stream silent this long
/// is dead.
pub const QUIET_LIMIT: Duration = Duration::from_secs(120);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// After a rebind: the network changed, not control.
const BACKOFF_REBIND: Duration = Duration::from_millis(100);

/// A call, by the session's count.
pub type CallId = u64;

/// Who the node is to control.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    /// Without the home region's report (the session adds it).
    pub hostinfo: Hostinfo,
    pub auth_key: Option<String>,
    pub ephemeral: bool,
}

/// Why control will not have this node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("control refused the node: {0}")]
    Refused(String),
    #[error("the node key expired")]
    KeyExpired,
    #[error("the node needs a login{}", .0.as_deref().map(|u| format!(" at {u}")).unwrap_or_default())]
    NeedsLogin(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// Before the first registration: control could not be reached.
    #[error("control: {0}")]
    Unreachable(String),
    #[error("{0}")]
    Refused(#[from] Refusal),
    #[error("control: {0}")]
    Api(#[from] ApiError),
}

/// The answer to a call, as the driver's transport gives it.
#[derive(Debug, Clone)]
pub enum Answer {
    /// A whole call's answer.
    Whole {
        status: u16,
        body: Vec<u8>,
    },
    /// One response on a map stream (keepalives too).
    Map(Box<MapResponse>),
    /// The map stream ended.
    MapEnded,
    Failed(ApiError),
}

/// What the driver should do, or hear.
#[derive(Debug, Clone)]
pub enum Event {
    /// Open a control connection (`GET /key` first, then the upgrade), and
    /// say [`connected`](ControlSession::connected) or
    /// [`connect_failed`](ControlSession::connect_failed).
    Connect,
    /// Drop the control connection and what is in flight on it.
    Disconnect,
    /// Make a call: `stream` ones are answered as a map stream.
    Send {
        id: CallId,
        call: Call,
        stream: bool,
    },
    /// Registered (the first time and after each reconnect).
    Registered,
    /// A map response (not a keepalive): sync its tailnet-lock info, then
    /// apply it.
    Map(Box<MapResponse>),
    /// The session is over: before the first registration, control could
    /// not be reached or refused the node.
    Ended(SessionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting to connect again, until then.
    Waiting(Instant),
    Connecting,
    Registering(CallId),
    /// The stream is open (and the session registered).
    Streaming(CallId),
    Ended,
}

/// See the module docs.
pub struct ControlSession {
    config: SessionConfig,
    phase: Phase,
    /// Registered at least once: failures after that are retried.
    started: bool,
    backoff: Duration,
    next_id: CallId,
    /// When the stream was last heard.
    heard: Instant,
    /// What updates tell control, and whether one is due or in flight.
    endpoints: Vec<(SocketAddr, EndpointType)>,
    home: HomeReport,
    tka_head: String,
    update_due: bool,
    update: Option<CallId>,
    events: VecDeque<Event>,
}

impl ControlSession {
    /// A session that connects right away.
    pub fn new(config: SessionConfig, tka_head: String, now: Instant) -> Self {
        let mut s = Self {
            config,
            phase: Phase::Connecting,
            started: false,
            backoff: BACKOFF_FIRST,
            next_id: 0,
            heard: now,
            endpoints: Vec::new(),
            home: (None, Default::default()),
            tka_head,
            update_due: true,
            update: None,
            events: VecDeque::new(),
        };
        s.events.push_back(Event::Connect);
        s
    }

    // ------------------------------------------------------------ inputs --

    /// The connection asked for is up.
    pub fn connected(&mut self, _now: Instant) {
        if self.phase != Phase::Connecting {
            return;
        }
        let call = Call::register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: self.config.node_key,
            auth: self
                .config
                .auth_key
                .clone()
                .map(|auth_key| RegisterAuth { auth_key }),
            hostinfo: self.hostinfo(&(None, Default::default())),
            ephemeral: self.config.ephemeral,
            ..Default::default()
        });
        let id = self.send(call, false);
        self.phase = Phase::Registering(id);
    }

    /// The connection asked for could not be made.
    pub fn connect_failed(&mut self, now: Instant, reason: &str) {
        if self.phase != Phase::Connecting {
            return;
        }
        if !self.started {
            return self.end(SessionError::Unreachable(reason.to_owned()));
        }
        tracing::warn!("reconnecting to control: {reason}");
        self.retry(now);
    }

    /// The connection dropped (the driver noticed).
    pub fn disconnected(&mut self, now: Instant) {
        match self.phase {
            Phase::Ended | Phase::Waiting(_) => {}
            _ if !self.started => {
                self.end(SessionError::Unreachable("the connection dropped".into()))
            }
            _ => self.retry(now),
        }
    }

    /// A call's answer.
    pub fn answer(&mut self, now: Instant, id: CallId, answer: Answer) {
        match self.phase {
            Phase::Registering(r) if r == id => self.on_register(now, answer),
            Phase::Streaming(s) if s == id => self.on_stream(now, answer),
            _ if self.update == Some(id) => {
                // Not needed (the stream brings the changes): only its end.
                if matches!(
                    answer,
                    Answer::MapEnded | Answer::Failed(_) | Answer::Whole { .. }
                ) {
                    if let Answer::Failed(e) = &answer {
                        tracing::debug!("endpoint update: {e}");
                    }
                    self.update = None;
                    self.maybe_update();
                }
            }
            // Of a connection gone.
            _ => {}
        }
    }

    /// The network changed: a new connection, soon.
    pub fn rebind(&mut self, now: Instant) {
        if matches!(self.phase, Phase::Ended) || !self.started {
            return;
        }
        tracing::debug!("rebind: reconnecting to control");
        self.backoff = BACKOFF_REBIND;
        self.events.push_back(Event::Disconnect);
        self.retry(now);
    }

    /// Our endpoints, for the next update.
    pub fn set_endpoints(&mut self, endpoints: Vec<(SocketAddr, EndpointType)>) {
        if endpoints != self.endpoints {
            self.endpoints = endpoints;
            self.update_soon();
        }
    }

    /// Our home region and latencies, for the next update.
    pub fn set_home(&mut self, home: HomeReport) {
        if home != self.home {
            self.home = home;
            self.update_soon();
        }
    }

    /// Our tailnet-lock head, for updates and the next stream.
    pub fn set_tka_head(&mut self, head: String) {
        if head != self.tka_head {
            self.tka_head = head;
            self.update_soon();
        }
    }

    /// Call when [`poll_timeout`](Self::poll_timeout) is due.
    pub fn handle_timeout(&mut self, now: Instant) {
        match self.phase {
            Phase::Waiting(at) if now >= at => {
                self.phase = Phase::Connecting;
                self.events.push_back(Event::Connect);
            }
            Phase::Streaming(_) if now >= self.heard + QUIET_LIMIT => {
                tracing::debug!("the map stream went quiet; reconnecting");
                self.events.push_back(Event::Disconnect);
                self.retry(now);
            }
            _ => {}
        }
    }

    // ----------------------------------------------------------- outputs --

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`handle_timeout`](Self::handle_timeout) is due, if ever.
    pub fn poll_timeout(&self) -> Option<Instant> {
        match self.phase {
            Phase::Waiting(at) => Some(at),
            Phase::Streaming(_) => Some(self.heard + QUIET_LIMIT),
            _ => None,
        }
    }

    pub fn is_ended(&self) -> bool {
        self.phase == Phase::Ended
    }

    // ----------------------------------------------------------- inside --

    fn on_register(&mut self, now: Instant, answer: Answer) {
        let refusal = match answer {
            Answer::Whole { status, body } => match api::parse_register(status, &body) {
                Ok(resp) if !resp.error.is_empty() => Some(Refusal::Refused(resp.error).into()),
                Ok(resp) if resp.node_key_expired => Some(Refusal::KeyExpired.into()),
                Ok(resp) if !resp.auth_url.is_empty() => {
                    Some(Refusal::NeedsLogin(Some(resp.auth_url)).into())
                }
                Ok(resp) if !resp.machine_authorized => Some(Refusal::NeedsLogin(None).into()),
                Ok(_) => None,
                Err(e) => Some(SessionError::Api(e)),
            },
            Answer::Failed(e) => Some(SessionError::Api(e)),
            Answer::Map(_) | Answer::MapEnded => Some(SessionError::Api(ApiError(
                "register answered as a stream".into(),
            ))),
        };
        if let Some(error) = refusal {
            if !self.started {
                return self.end(error);
            }
            tracing::warn!("reconnecting to control: {error}");
            self.events.push_back(Event::Disconnect);
            return self.retry(now);
        }
        self.started = true;
        self.events.push_back(Event::Registered);
        let call = Call::map(&self.map_request(true));
        let id = self.send(call, true);
        self.phase = Phase::Streaming(id);
        self.heard = now;
        // A fresh connection hears our endpoints again.
        self.update = None;
        self.update_soon();
    }

    fn on_stream(&mut self, now: Instant, answer: Answer) {
        match answer {
            Answer::Map(resp) => {
                self.heard = now;
                self.backoff = BACKOFF_FIRST;
                if !resp.keep_alive {
                    self.events.push_back(Event::Map(resp));
                }
            }
            Answer::MapEnded | Answer::Whole { .. } => {
                tracing::debug!("the map stream ended; reconnecting");
                self.events.push_back(Event::Disconnect);
                self.retry(now);
            }
            Answer::Failed(e) => {
                tracing::debug!("map stream: {e}");
                self.events.push_back(Event::Disconnect);
                self.retry(now);
            }
        }
    }

    /// Wait, then connect again (the wait doubling each time).
    fn retry(&mut self, now: Instant) {
        self.update = None;
        self.phase = Phase::Waiting(now + self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    fn end(&mut self, error: SessionError) {
        self.phase = Phase::Ended;
        self.events.push_back(Event::Ended(error));
    }

    fn send(&mut self, call: Call, stream: bool) -> CallId {
        self.next_id += 1;
        let id = self.next_id;
        self.events.push_back(Event::Send { id, call, stream });
        id
    }

    fn update_soon(&mut self) {
        self.update_due = true;
        self.maybe_update();
    }

    /// One update at a time, with what is current when it goes.
    fn maybe_update(&mut self) {
        if !self.update_due || self.update.is_some() || !matches!(self.phase, Phase::Streaming(_)) {
            return;
        }
        self.update_due = false;
        let call = Call::map(&self.map_request(false));
        self.update = Some(self.send(call, true));
    }

    fn map_request(&self, stream: bool) -> MapRequest {
        let (endpoints, home) = if stream {
            // The stream itself carries no endpoints: updates do.
            (&[][..], &(None, Default::default()))
        } else {
            (&self.endpoints[..], &self.home)
        };
        MapRequest {
            version: CAPABILITY_VERSION,
            node_key: self.config.node_key,
            disco_key: self.config.disco_key,
            stream,
            keep_alive: stream,
            omit_peers: !stream,
            hostinfo: self.hostinfo(home),
            endpoints: endpoints.iter().map(|(e, _)| *e).collect(),
            endpoint_types: endpoints.iter().map(|(_, t)| *t as u8).collect(),
            tka_head: self.tka_head.clone(),
        }
    }

    fn hostinfo(&self, home: &HomeReport) -> Hostinfo {
        Hostinfo {
            net_info: home.0.map(|preferred_derp| NetInfo {
                preferred_derp,
                derp_latency: home.1.clone(),
            }),
            ..self.config.hostinfo.clone()
        }
    }
}

#[cfg(test)]
mod tests;
