//! The control task: the session's connections over the app's streams
//! (`GET /key`, then [`ControlConn`]), its calls by id, and tailnet-lock
//! sync ([`LockSync`]) before a map response applies.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use embassy_futures::select::{select3, Either3};
use embedded_io_async::{Read, Write};

use mesh_core::control::api::{self, ApiError};
use mesh_core::control::conn::{self, ControlConn};
use mesh_core::control::http1;
use mesh_core::control::session::{Answer, CallId, Event};
use mesh_core::control::types::MapResponse;
use mesh_core::keys::NodePublic;
use mesh_core::lock::sync::{LockSync, Step};
use mesh_core::node::NodeCore;

use crate::{at, now, Dial, Mesh, MeshError, Tls};

/// A connection to control (dial, TLS, `GET /key`, the second dial) gives
/// up after this long: a hanging handshake must not stall control.
const CONNECT_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_secs(30);

/// Control's URL, taken apart.
pub(crate) struct Url {
    https: bool,
    host: String,
    port: u16,
    authority: String,
}

impl Url {
    pub(crate) fn parse(url: &str) -> Result<Self, MeshError> {
        let bad = || MeshError::Url(url.to_string());
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(bad());
        };
        let authority = rest.split('/').next().unwrap_or_default();
        let default = if https { 443 } else { 80 };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => (
                host.trim_matches(['[', ']']),
                port.parse().map_err(|_| bad())?,
            ),
            _ => (authority.trim_matches(['[', ']']), default),
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            https,
            host: host.to_string(),
            port,
            authority: authority.to_string(),
        })
    }

    fn tls(&self) -> Tls<'_> {
        if self.https {
            // Noise authenticates control: TLS only hides it.
            Tls::Unverified(&self.host)
        } else {
            Tls::None
        }
    }
}

/// Who a call on the connection is for.
enum Owner {
    Session(CallId),
    Lock,
}

struct Live<C> {
    conn: ControlConn,
    stream: C,
    calls: BTreeMap<u32, Owner>,
}

/// A tailnet-lock sync in progress, and the map responses held until it
/// is done (in order).
struct Syncing {
    sync: LockSync,
    held: VecDeque<Box<MapResponse>>,
}

impl Mesh {
    pub(crate) async fn control_task<D: Dial>(&self, url: &Url, dial: &D) -> Result<(), MeshError> {
        let mut live: Option<Live<D::Conn<'_>>> = None;
        let mut syncing: Option<Syncing> = None;
        let mut buf = vec![0u8; 4096];
        loop {
            // What the session wants.
            loop {
                let event = self.inner.borrow_mut().session.poll_event();
                let Some(event) = event else { break };
                match event {
                    Event::Connect => {
                        live = None;
                        let connecting = embassy_time::with_timeout(
                            CONNECT_TIMEOUT,
                            self.connect_control(url, dial),
                        );
                        match connecting.await {
                            Ok(Ok(l)) => live = Some(l),
                            Ok(Err(e)) => self.inner.borrow_mut().session.connect_failed(now(), &e),
                            Err(_) => self
                                .inner
                                .borrow_mut()
                                .session
                                .connect_failed(now(), "connecting timed out"),
                        }
                    }
                    Event::Disconnect => live = None,
                    Event::Send { id, call, stream } => {
                        let sent = match &mut live {
                            Some(l) => {
                                let cid = if stream {
                                    l.conn.map(&call)
                                } else {
                                    l.conn.call(&call)
                                };
                                cid.map(|cid| {
                                    l.calls.insert(cid, Owner::Session(id));
                                })
                                .map_err(|e| e.to_string())
                            }
                            None => Err(String::from("no control connection")),
                        };
                        if let Err(e) = sent {
                            self.inner.borrow_mut().session.answer(
                                now(),
                                id,
                                Answer::Failed(ApiError(e)),
                            );
                        }
                    }
                    Event::Registered => tracing::debug!("registered with control"),
                    Event::Map(resp) => self.on_map(resp, &mut syncing, &mut live),
                    Event::Ended(e) => return Err(MeshError::Control(e)),
                }
            }
            if let Some(l) = &mut live {
                if let Some(out) = l.conn.poll_transmit() {
                    if l.stream.write_all(&out).await.is_err() || l.stream.flush().await.is_err() {
                        live = None;
                        self.dropped(&mut syncing, &mut live);
                        continue;
                    }
                }
            }

            let deadline = self.inner.borrow().session.poll_timeout();
            let timer = async {
                match deadline {
                    Some(t) => embassy_time::Timer::at(at(t)).await,
                    None => core::future::pending().await,
                }
            };
            let read = async {
                match &mut live {
                    Some(l) => l.stream.read(&mut buf).await.map_err(|_| ()),
                    None => core::future::pending().await,
                }
            };
            let woke = select3(read, self.control_wake.wait(), timer).await;
            match woke {
                Either3::First(Ok(n)) if n > 0 => {
                    let l = live.as_mut().expect("read on a connection");
                    let input = l.conn.handle_input(&buf[..n]);
                    self.conn_events(&mut syncing, &mut live);
                    if let Err(e) = input {
                        tracing::debug!("control: {e}");
                        live = None;
                        self.dropped(&mut syncing, &mut live);
                    }
                }
                Either3::First(_) => {
                    tracing::debug!("control: the connection closed");
                    live = None;
                    self.dropped(&mut syncing, &mut live);
                }
                Either3::Second(()) => {}
                Either3::Third(()) => self.inner.borrow_mut().session.handle_timeout(now()),
            }
        }
    }

    /// `GET /key` on a stream of its own, then the control connection.
    async fn connect_control<'d, D: Dial>(
        &self,
        url: &Url,
        dial: &'d D,
    ) -> Result<Live<D::Conn<'d>>, String> {
        if D::WEBSOCKET {
            return self.connect_websocket(url, dial).await;
        }
        let server_key = {
            let mut stream = dial
                .dial(&url.host, url.port, url.tls())
                .await
                .map_err(|e| e.to_string())?;
            let request = http1::request(
                "GET",
                &api::key_path(),
                &url.authority,
                &["Connection: close"],
            );
            stream
                .write_all(&request)
                .await
                .map_err(|e| format!("GET /key: {e:?}"))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("GET /key: {e:?}"))?;
            let mut raw = Vec::new();
            let mut chunk = vec![0u8; 1024];
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
                if raw.len() > 64 << 10 {
                    return Err(String::from("GET /key: too large"));
                }
            }
            let (head, used) = http1::parse_head(&raw)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| String::from("GET /key: no response"))?;
            let body = http1::body(&head, raw[used..].to_vec()).map_err(|e| e.to_string())?;
            api::parse_server_key(head.status, &body).map_err(|e| e.to_string())?
        };
        let stream = dial
            .dial(&url.host, url.port, url.tls())
            .await
            .map_err(|e| e.to_string())?;
        let conn = ControlConn::new(
            &url.authority,
            &self.config.machine_key,
            &server_key,
            self.config.http2,
        )
        .map_err(|e| e.to_string())?;
        Ok(Live {
            conn,
            stream,
            calls: BTreeMap::new(),
        })
    }

    /// The WebSocket form: `/key` by GET, then the upgrade the Dial makes.
    async fn connect_websocket<'d, D: Dial>(
        &self,
        url: &Url,
        dial: &'d D,
    ) -> Result<Live<D::Conn<'d>>, String> {
        let scheme = if url.https { "https" } else { "http" };
        let (status, body) = dial
            .get(&format!("{scheme}://{}{}", url.authority, api::key_path()))
            .await
            .map_err(|e| format!("GET /key: {e}"))?;
        let server_key = api::parse_server_key(status, &body).map_err(|e| e.to_string())?;
        let (conn, path) = ControlConn::upgraded(
            &url.authority,
            &self.config.machine_key,
            &server_key,
            self.config.http2,
        )
        .map_err(|e| e.to_string())?;
        let ws = if url.https { "wss" } else { "ws" };
        let stream = dial
            .websocket(
                &format!("{ws}://{}{path}", url.authority),
                api::WEBSOCKET_PROTOCOL,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(Live {
            conn,
            stream,
            calls: BTreeMap::new(),
        })
    }

    /// The connection's events, to the session or the lock sync.
    fn conn_events<C>(&self, syncing: &mut Option<Syncing>, live: &mut Option<Live<C>>) {
        loop {
            let Some(l) = live.as_mut() else { return };
            let Some(event) = l.conn.poll_event() else {
                return;
            };
            let t = now();
            let (id, answer) = match event {
                conn::Event::Ready => {
                    self.inner.borrow_mut().session.connected(t);
                    continue;
                }
                conn::Event::GoingAway => {
                    *live = None;
                    self.dropped(syncing, live);
                    return;
                }
                conn::Event::Answer { id, status, body } => (id, Ok((status, body))),
                conn::Event::Map { id, response } => (id, Err(Answer::Map(response))),
                conn::Event::MapEnded { id } => (id, Err(Answer::MapEnded)),
                conn::Event::Failed { id, error } => (id, Err(Answer::Failed(error))),
            };
            // A stream's call stays until it ends; others go with their answer.
            let streaming = matches!(answer, Err(Answer::Map(_)));
            let owner = match l.calls.get(&id) {
                Some(Owner::Session(sid)) => Some(Some(*sid)),
                Some(Owner::Lock) => Some(None),
                None => None,
            };
            if !streaming || owner == Some(None) {
                l.calls.remove(&id);
            }
            match owner {
                Some(Some(sid)) => {
                    let answer = match answer {
                        Ok((status, body)) => Answer::Whole { status, body },
                        Err(a) => a,
                    };
                    self.inner.borrow_mut().session.answer(t, sid, answer);
                }
                Some(None) => {
                    let answered = match answer {
                        Ok(whole) => Ok(whole),
                        Err(Answer::Failed(e)) => Err(e.0),
                        Err(_) => Err(String::from("a lock call answered as a stream")),
                    };
                    self.lock_answer(answered, syncing, live);
                }
                None => {}
            }
        }
    }

    /// The connection went: the session hears it, a sync in flight ends.
    fn dropped<C>(&self, syncing: &mut Option<Syncing>, live: &mut Option<Live<C>>) {
        self.inner.borrow_mut().session.disconnected(now());
        if syncing.is_some() {
            self.lock_answer(
                Err(String::from("the control connection dropped")),
                syncing,
                live,
            );
        }
    }

    /// A map response from the session: sync the lock first if it says so.
    fn on_map<C>(
        &self,
        mut resp: Box<MapResponse>,
        syncing: &mut Option<Syncing>,
        live: &mut Option<Live<C>>,
    ) {
        if let Some(s) = syncing {
            s.held.push_back(resp);
            return;
        }
        let info = resp.tka_info.take();
        let lock = {
            let mut inner = self.inner.borrow_mut();
            let inner = &mut *inner;
            match (&info, inner.core.as_ref(), inner.start.as_ref()) {
                // Running: only when the head moved.
                (Some(info), Some(core), _) if core.lock().needs_sync(info) => {
                    Some(core.lock().clone())
                }
                // Starting: every announcement.
                (Some(_), None, Some(start)) => Some(start.lock.clone()),
                _ => None,
            }
        };
        let (Some(info), Some(lock)) = (info, lock) else {
            return self.apply(resp);
        };
        let node_key = NodePublic(self.config.node_key.public());
        let (sync, step) = LockSync::start(node_key, info, lock);
        let mut held = VecDeque::new();
        held.push_back(resp);
        *syncing = Some(Syncing { sync, held });
        self.lock_step(step, syncing, live);
    }

    fn lock_answer<C>(
        &self,
        answered: Result<(u16, Vec<u8>), String>,
        syncing: &mut Option<Syncing>,
        live: &mut Option<Live<C>>,
    ) {
        let Some(s) = syncing.as_mut() else { return };
        let step = s.sync.answer(answered);
        self.lock_step(step, syncing, live);
    }

    fn lock_step<C>(&self, step: Step, syncing: &mut Option<Syncing>, live: &mut Option<Live<C>>) {
        match step {
            Step::Call(call) => {
                let sent = live.as_mut().map(|l| {
                    l.conn
                        .call(&call)
                        .map(|cid| l.calls.insert(cid, Owner::Lock))
                });
                if !matches!(sent, Some(Ok(_))) {
                    self.lock_answer(
                        Err(String::from("no control connection for tailnet lock")),
                        syncing,
                        live,
                    );
                }
            }
            Step::Done(lock) => {
                let head = lock.head_text();
                {
                    let mut inner = self.inner.borrow_mut();
                    let inner = &mut *inner;
                    match (inner.core.as_mut(), inner.start.as_mut()) {
                        (Some(core), _) => core.set_lock(lock),
                        (None, Some(start)) => start.lock = lock,
                        _ => {}
                    }
                    inner.session.set_tka_head(head);
                }
                self.control_wake.signal(());
                let held = syncing.take().map(|s| s.held).unwrap_or_default();
                for resp in held {
                    self.on_map(resp, syncing, live);
                }
            }
        }
    }

    /// Into the node, or (before it is up) into the start's netmap.
    fn apply(&self, mut resp: Box<MapResponse>) {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        if let Some(core) = inner.core.as_mut() {
            core.apply_map(*resp);
            self.node_wake.signal(());
            return;
        }
        let Some(start) = inner.start.as_mut() else {
            return;
        };
        mesh_core::filter::apply_update(
            &mut start.filter_sets,
            resp.packet_filter.take(),
            resp.packet_filters.take(),
        );
        start.netmap.apply(*resp);
        if start.netmap.self_node.is_none() {
            return;
        }
        let start = inner.start.take().expect("starting");
        let mut core = NodeCore::new(
            self.config.node_key.clone(),
            start.paths.expect("paths"),
            start.netmap,
            start.filter_sets,
            start.lock,
            self.config.settings,
            now(),
        );
        core.set_udp_ports(0, None);
        tracing::info!("on the mesh as {:?}", core.netmap().self_addresses());
        inner.core = Some(core);
        for waker in inner.joined.drain(..) {
            waker.wake();
        }
        self.node_wake.signal(());
    }
}
