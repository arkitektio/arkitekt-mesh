//! The core's control connection (`ControlConn`, our own HTTP/2) against
//! ionskale in the mesh lab, both ways in: the HTTP upgrade (`POST
//! /ts2021`, as the embassy driver will make it) and the WebSocket form
//! (`GET /ts2021`, as a browser makes it), each over TLS.

mod mesh_lab;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mesh::control::api::{self, Call};
use mesh::control::conn::{CallId, ControlConn, Event};
use mesh::control::netmap::NetMap;
use mesh::control::types::*;
use mesh::driver::net::{self, BaseUrl, Tls};
use mesh::keys::{DiscoPublic, MachinePublic, NodeIdentity, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

async fn server_key(base: &BaseUrl) -> MachinePublic {
    let (status, body) = net::get(base, &api::key_path()).await.unwrap();
    api::parse_server_key(status, &body).unwrap()
}

/// How the connection's bytes move: a TLS stream, or WebSocket messages.
enum Wire {
    Stream(net::BoxIo),
    Ws(Box<tokio_tungstenite::WebSocketStream<net::BoxIo>>),
}

impl Wire {
    async fn send(&mut self, data: Vec<u8>) {
        match self {
            Wire::Stream(io) => io.write_all(&data).await.unwrap(),
            Wire::Ws(ws) => ws.send(Message::binary(data)).await.unwrap(),
        }
    }

    async fn recv(&mut self) -> Vec<u8> {
        match self {
            Wire::Stream(io) => {
                let mut buf = vec![0u8; 4096];
                let n = io.read(&mut buf).await.unwrap();
                assert!(n > 0, "ionskale closed the connection");
                buf.truncate(n);
                buf
            }
            Wire::Ws(ws) => loop {
                match ws
                    .next()
                    .await
                    .expect("ionskale closed the WebSocket")
                    .unwrap()
                {
                    Message::Binary(data) => return data.to_vec(),
                    Message::Close(frame) => panic!("ionskale closed the WebSocket: {frame:?}"),
                    _ => {}
                }
            },
        }
    }
}

struct Driver {
    conn: ControlConn,
    wire: Wire,
}

impl Driver {
    async fn until<T>(&mut self, mut done: impl FnMut(Event) -> Option<T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(out) = self.conn.poll_transmit() {
                    self.wire.send(out).await;
                }
                while let Some(event) = self.conn.poll_event() {
                    if let Some(t) = done(event) {
                        if let Some(out) = self.conn.poll_transmit() {
                            self.wire.send(out).await;
                        }
                        return t;
                    }
                }
                let data = self.wire.recv().await;
                self.conn.handle_input(&data).unwrap();
            }
        })
        .await
        .expect("timed out")
    }

    async fn answer(&mut self, id: CallId) -> (u16, Vec<u8>) {
        self.until(|e| match e {
            Event::Answer {
                id: i,
                status,
                body,
            } if i == id => Some((status, body)),
            Event::Failed { id: i, error } if i == id => panic!("{error}"),
            _ => None,
        })
        .await
    }
}

/// Register with the lab key and read the first netmap off the stream.
async fn join(d: &mut Driver, lab: &mesh_lab::Lab, id: &NodeIdentity, hostname: &str) -> NetMap {
    d.until(|e| matches!(e, Event::Ready).then_some(())).await;
    let hostinfo = Hostinfo {
        hostname: hostname.into(),
        os: std::env::consts::OS.into(),
        ipn_version: "arkitekt-mesh-test".into(),
        ..Default::default()
    };
    let register = d
        .conn
        .call(&Call::register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            auth: Some(RegisterAuth {
                auth_key: lab.key.clone(),
            }),
            hostinfo: hostinfo.clone(),
            ephemeral: true,
            ..Default::default()
        }))
        .unwrap();
    let (status, body) = d.answer(register).await;
    let resp = api::parse_register(status, &body).unwrap();
    assert!(resp.error.is_empty(), "{}", resp.error);
    assert!(resp.machine_authorized, "the lab key is pre-authorized");

    let stream = d
        .conn
        .map(&Call::map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            disco_key: DiscoPublic(PrivateKey::generate().public()),
            stream: true,
            keep_alive: true,
            hostinfo,
            ..Default::default()
        }))
        .unwrap();
    let first = d
        .until(|e| match e {
            Event::Map { id, response } if id == stream => Some(response),
            Event::Failed { id, error } if id == stream => panic!("{error}"),
            Event::MapEnded { id } if id == stream => panic!("the map stream ended"),
            _ => None,
        })
        .await;
    let mut netmap = NetMap::default();
    netmap.apply(*first);
    assert_eq!(
        netmap.self_node.as_ref().expect("self node").key,
        id.node_public()
    );
    netmap
}

#[tokio::test]
async fn over_the_http_upgrade() {
    let Some(lab) = mesh_lab::lab() else { return };
    let base = BaseUrl::parse(&lab.url).unwrap();
    let key = server_key(&base).await;
    let id = NodeIdentity::generate();
    let conn =
        ControlConn::new(&base.authority(), &id.machine.0, &key, Default::default()).unwrap();
    // Noise authenticates control: TLS needs no verifying here.
    let io = net::connect(&base.host, base.port, Tls::NoVerify)
        .await
        .unwrap();
    let mut d = Driver {
        conn,
        wire: Wire::Stream(io),
    };
    let netmap = join(&mut d, &lab, &id, &lab.hostname("sansio-h1")).await;
    assert!(
        netmap.peer_by_name(&lab.peer).is_some(),
        "the lab peer is in the netmap"
    );
}

#[tokio::test]
async fn over_a_websocket() {
    mesh_lab::init_tracing();
    let Some(lab) = mesh_lab::lab() else { return };
    let base = BaseUrl::parse(&lab.url).unwrap();
    let key = server_key(&base).await;
    let id = NodeIdentity::generate();
    let (conn, path) =
        ControlConn::upgraded(&base.authority(), &id.machine.0, &key, Default::default()).unwrap();
    let io = net::connect(&base.host, base.port, Tls::NoVerify)
        .await
        .unwrap();
    let mut request = format!("wss://{}{path}", base.authority())
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        api::WEBSOCKET_PROTOCOL.parse().unwrap(),
    );
    let (ws, response) = tokio_tungstenite::client_async(request, io).await.unwrap();
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        api::WEBSOCKET_PROTOCOL
    );
    let mut d = Driver {
        conn,
        wire: Wire::Ws(Box::new(ws)),
    };
    let netmap = join(&mut d, &lab, &id, &lab.hostname("sansio-ws")).await;
    assert!(
        netmap.peer_by_name(&lab.peer).is_some(),
        "the lab peer is in the netmap"
    );
}
