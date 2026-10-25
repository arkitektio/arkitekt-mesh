//! The core's control connection without I/O (`ControlConn`: the ts2021
//! upgrade, Noise and our own HTTP/2, as the drivers without std use it)
//! against tailscale's test control server, moved over tokio TCP here.
//! Go's HPACK encoder indexes and Huffman-codes; its map stream is long.

mod common;

use std::time::Duration;

use mesh::control::api::{self, Call};
use mesh::control::conn::{CallId, ControlConn, Event};
use mesh::control::http1;
use mesh::control::netmap::NetMap;
use mesh::control::types::*;
use mesh::keys::{DiscoPublic, NodeIdentity, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `host:port` of an `http://` URL.
fn authority(url: &str) -> String {
    url.strip_prefix("http://")
        .expect("the harness serves plain HTTP")
        .trim_end_matches('/')
        .to_owned()
}

/// `GET /key` on a connection of its own, as a driver without std does it.
async fn server_key(authority: &str) -> mesh::keys::MachinePublic {
    let mut tcp = TcpStream::connect(authority).await.unwrap();
    let request = http1::request("GET", &api::key_path(), authority, &["Connection: close"]);
    tcp.write_all(&request).await.unwrap();
    let mut raw = Vec::new();
    tcp.read_to_end(&mut raw).await.unwrap();
    let (head, used) = http1::parse_head(&raw).unwrap().expect("a response head");
    let body = http1::body(&head, raw[used..].to_vec()).unwrap();
    api::parse_server_key(head.status, &body).unwrap()
}

/// The driver: bytes between the socket and the connection, until `done`
/// takes an event and says so.
struct Driver {
    conn: ControlConn,
    tcp: TcpStream,
}

impl Driver {
    async fn until<T>(&mut self, mut done: impl FnMut(Event) -> Option<T>) -> T {
        let mut buf = vec![0u8; 4096];
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(out) = self.conn.poll_transmit() {
                    self.tcp.write_all(&out).await.unwrap();
                }
                while let Some(event) = self.conn.poll_event() {
                    if let Some(t) = done(event) {
                        if let Some(out) = self.conn.poll_transmit() {
                            self.tcp.write_all(&out).await.unwrap();
                        }
                        return t;
                    }
                }
                let n = self.tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "control closed the connection");
                self.conn.handle_input(&buf[..n]).unwrap();
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

fn hostinfo(name: &str) -> Hostinfo {
    Hostinfo {
        hostname: name.into(),
        os: std::env::consts::OS.into(),
        ipn_version: "arkitekt-mesh-test".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn register_and_stream_the_netmap_over_our_http2() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let authority = authority(&h.ready.control_url);
    let key = server_key(&authority).await;
    let id = NodeIdentity::generate();
    let disco = DiscoPublic(PrivateKey::generate().public());

    let conn = ControlConn::new(&authority, &id.machine.0, &key, Default::default()).unwrap();
    let tcp = TcpStream::connect(&authority).await.unwrap();
    let mut d = Driver { conn, tcp };
    d.until(|e| matches!(e, Event::Ready).then_some(())).await;

    let register = d
        .conn
        .call(&Call::register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            auth: Some(RegisterAuth {
                auth_key: h.ready.auth_key.clone(),
            }),
            hostinfo: hostinfo("rusty-sansio"),
            ..Default::default()
        }))
        .unwrap();
    let (status, body) = d.answer(register).await;
    let resp = api::parse_register(status, &body).unwrap();
    assert!(resp.error.is_empty(), "{}", resp.error);
    assert!(resp.auth_url.is_empty());

    // The update with our disco key: answered, then ended.
    let update = d
        .conn
        .map(&Call::map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            disco_key: disco,
            omit_peers: true,
            hostinfo: hostinfo("rusty-sansio"),
            ..Default::default()
        }))
        .unwrap();
    d.until(|e| match e {
        Event::MapEnded { id } if id == update => Some(()),
        Event::Failed { id, error } if id == update => panic!("{error}"),
        _ => None,
    })
    .await;

    // The stream: a first netmap with the peer, then keepalives.
    let stream = d
        .conn
        .map(&Call::map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            disco_key: disco,
            stream: true,
            keep_alive: true,
            hostinfo: hostinfo("rusty-sansio"),
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
    let me = netmap.self_node.as_ref().expect("self node");
    assert_eq!(me.key, id.node_public());
    assert!(!netmap.self_addresses().is_empty());
    let peer = netmap
        .peer_by_name(&h.ready.peer_name)
        .expect("the peer is in the netmap");
    assert_eq!(peer.addresses[0].to_string(), h.ready.peer_ip);
    assert!(!netmap.derp_regions.is_empty());

    // Other calls go on beside the open stream.
    let again = d
        .conn
        .call(&Call::register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            auth: Some(RegisterAuth {
                auth_key: h.ready.auth_key.clone(),
            }),
            hostinfo: hostinfo("rusty-sansio"),
            ..Default::default()
        }))
        .unwrap();
    let (status, body) = d.answer(again).await;
    let resp = api::parse_register(status, &body).unwrap();
    assert!(resp.error.is_empty(), "{}", resp.error);
    d.conn.cancel(stream);
}

#[tokio::test]
async fn a_refused_upgrade_is_an_error() {
    let Some(h) = common::start().await else {
        return;
    };
    let authority = authority(&h.ready.control_url);
    // A Noise key that is not the server's: the handshake fails.
    let wrong = mesh::keys::MachinePublic(PrivateKey::generate().public());
    let id = NodeIdentity::generate();
    let mut conn = ControlConn::new(&authority, &id.machine.0, &wrong, Default::default()).unwrap();
    let mut tcp = TcpStream::connect(&authority).await.unwrap();
    tcp.write_all(&conn.poll_transmit().unwrap()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = tcp.read(&mut buf).await.unwrap();
            if n == 0 {
                return Ok::<(), mesh::control::conn::ConnError>(());
            }
            conn.handle_input(&buf[..n])?;
        }
    })
    .await
    .expect("timed out");
    // Either the server answers with an error or closes the connection;
    // the connection never becomes ready.
    let _ = result;
    assert!(!conn.is_ready());
}
