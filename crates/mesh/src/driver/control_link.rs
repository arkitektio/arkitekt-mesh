//! The control session ([`ControlSession`], the core's policy) on tokio:
//! connections and calls through the `h2` crate's client, each as a task
//! whose answers come back on a channel. A bounded one: a map stream is
//! read no faster than the node takes its responses.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::control::ControlClient;
use super::node::{Config, MeshError};
use crate::control::api::{ApiError, Call};
use crate::control::session::{
    Answer, CallId, ControlSession, Event, Refusal, SessionConfig, SessionError,
};
use crate::control::types::{Hostinfo, MapResponse};
use crate::keys::{DiscoPublic, PrivateKey};
use mesh_core::time as clock;

/// What the link hands the node.
pub(super) enum Out {
    /// A map response (not a keepalive), tailnet-lock info and all.
    Map(Box<MapResponse>),
    /// Over: before the first registration, refused or unreachable.
    Ended(MeshError),
}

enum Input {
    /// A connection attempt of generation `.0` ended.
    Connected(u64, Result<ControlClient, String>),
    Answer(u64, CallId, Answer),
}

pub(super) struct ControlLink {
    pub(super) session: ControlSession,
    url: String,
    machine: PrivateKey,
    /// The connection, once up.
    client: Option<ControlClient>,
    /// Counts connections: what an old one's tasks send is dropped.
    generation: u64,
    /// The connection attempt and the calls on it (aborted on disconnect).
    tasks: Vec<JoinHandle<()>>,
    tx: mpsc::Sender<Input>,
    rx: mpsc::Receiver<Input>,
}

/// What we tell control about this host (the session adds the home region).
pub(super) fn hostinfo(config: &Config) -> Hostinfo {
    Hostinfo {
        ipn_version: concat!("arkitekt-mesh/", env!("CARGO_PKG_VERSION")).into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hostname: config.hostname.clone(),
        app: "arkitekt".into(),
        request_tags: config.tags.clone(),
        net_info: None,
    }
}

impl ControlLink {
    pub(super) fn new(config: &Config, disco: DiscoPublic, tka_head: String) -> Self {
        let session = ControlSession::new(
            SessionConfig {
                node_key: config.identity.node_public(),
                disco_key: disco,
                hostinfo: hostinfo(config),
                auth_key: config.auth_key.clone(),
                ephemeral: config.ephemeral,
            },
            tka_head,
            clock::now(),
        );
        let (tx, rx) = mpsc::channel(16);
        Self {
            session,
            url: config.control_url.clone(),
            machine: config.identity.machine.0.clone(),
            client: None,
            generation: 0,
            tasks: Vec::new(),
            tx,
            rx,
        }
    }

    /// The connection, for calls of the node's own (tailnet-lock sync).
    pub(super) fn client(&self) -> Option<&ControlClient> {
        self.client.as_ref()
    }

    /// Run the session until it has something for the node. Cancel-safe:
    /// it waits only on its channel and a timer.
    pub(super) async fn next(&mut self) -> Out {
        loop {
            while let Some(event) = self.session.poll_event() {
                match event {
                    Event::Connect => self.connect(),
                    Event::Disconnect => self.drop_connection(),
                    Event::Send { id, call, stream } => self.send(id, call, stream),
                    Event::Registered => tracing::debug!("registered with control"),
                    Event::Map(resp) => return Out::Map(resp),
                    Event::Ended(e) => {
                        self.drop_connection();
                        return Out::Ended(mesh_error(e));
                    }
                }
            }
            let deadline = self.session.poll_timeout().map(clock::to_std);
            let input = tokio::select! {
                input = self.rx.recv() => input.expect("the link holds a sender"),
                _ = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.session.handle_timeout(clock::now());
                    continue;
                }
            };
            match input {
                Input::Connected(g, _) if g != self.generation => {}
                Input::Connected(_, Ok(client)) => {
                    self.client = Some(client);
                    self.session.connected(clock::now());
                }
                Input::Connected(_, Err(e)) => self.session.connect_failed(clock::now(), &e),
                Input::Answer(g, _, _) if g != self.generation => {}
                Input::Answer(_, id, answer) => self.session.answer(clock::now(), id, answer),
            }
        }
    }

    fn connect(&mut self) {
        self.drop_connection();
        let (url, machine, tx, g) = (
            self.url.clone(),
            self.machine.clone(),
            self.tx.clone(),
            self.generation,
        );
        self.tasks.push(tokio::spawn(async move {
            let result = ControlClient::connect(&url, &machine)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(Input::Connected(g, result)).await;
        }));
    }

    fn drop_connection(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.client = None;
        self.generation += 1;
    }

    fn send(&mut self, id: CallId, call: Call, stream: bool) {
        let Some(client) = self.client.clone() else {
            return;
        };
        let (tx, g) = (self.tx.clone(), self.generation);
        self.tasks.retain(|t| !t.is_finished());
        self.tasks.push(tokio::spawn(async move {
            let answer = |a| Input::Answer(g, id, a);
            if !stream {
                let a = match client.call_whole(&call).await {
                    Ok((status, body)) => Answer::Whole { status, body },
                    Err(e) => Answer::Failed(ApiError(e.to_string())),
                };
                let _ = tx.send(answer(a)).await;
                return;
            }
            let mut s = match client.map_call(&call).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx
                        .send(answer(Answer::Failed(ApiError(e.to_string()))))
                        .await;
                    return;
                }
            };
            loop {
                let a = match s.next().await {
                    Ok(Some(resp)) => Answer::Map(Box::new(resp)),
                    Ok(None) => Answer::MapEnded,
                    Err(e) => Answer::Failed(ApiError(e.to_string())),
                };
                let last = !matches!(a, Answer::Map(_));
                if tx.send(answer(a)).await.is_err() || last {
                    return;
                }
            }
        }));
    }
}

impl Drop for ControlLink {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn mesh_error(e: SessionError) -> MeshError {
    match e {
        SessionError::Refused(Refusal::Refused(reason)) => MeshError::Refused(reason),
        SessionError::Refused(Refusal::KeyExpired) => MeshError::KeyExpired,
        SessionError::Refused(Refusal::NeedsLogin(url)) => MeshError::NeedsLogin(url),
        SessionError::Unreachable(reason) => {
            MeshError::Control(super::control::ControlError::Protocol(reason))
        }
        SessionError::Api(e) => MeshError::Control(e.into()),
    }
}
