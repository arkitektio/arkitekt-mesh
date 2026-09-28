//! The relay against the Go tsnet peer: a TURN client allocates on our
//! local TURN server and reaches the peer's UDP echo (:7) through the mesh;
//! a TCP forward reaches its HTTP server (:80).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mesh::driver::{Config, Node, TurnRelay};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use turn::client::{Client, ClientConfig};
use webrtc_util::Conn;

async fn node(h: &common::Harness, name: &str) -> Arc<Node> {
    Arc::new(
        Node::start(Config {
            control_url: h.ready.control_url.clone(),
            identity: NodeIdentity::generate(),
            auth_key: Some(h.ready.auth_key.clone()),
            hostname: name.into(),
            ephemeral: true,
            tags: vec![],
            direct: true,
            limits: Default::default(),
        })
        .await
        .unwrap(),
    )
}

#[tokio::test]
async fn turn_relays_over_the_mesh() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let node = node(&h, "rusty-turn").await;
    let relay = TurnRelay::start(node.udp_binder().unwrap()).await.unwrap();
    let info = relay.info().clone();
    let server = info.urls[0]
        .trim_start_matches("turn:")
        .trim_end_matches("?transport=udp")
        .to_owned();

    // A WebRTC stack's view: a local UDP socket talking TURN to 127.0.0.1.
    let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Client::new(ClientConfig {
        stun_serv_addr: server.clone(),
        turn_serv_addr: server,
        username: info.username.clone(),
        password: info.credential.clone(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn,
        vnet: None,
    })
    .await
    .unwrap();
    client.listen().await.unwrap();
    let allocation = client.allocate().await.unwrap();
    // The relayed address is ours on the mesh: what the SFU would answer to.
    let relayed = allocation.local_addr().unwrap();
    assert!(node.addresses().contains(&relayed.ip()), "{relayed}");

    let peer: SocketAddr = format!("{}:7", h.ready.peer_ip).parse().unwrap();
    let mut buf = [0u8; 1500];
    let mut echoed = false;
    for _ in 0..40 {
        allocation
            .send_to(b"through the relay", peer)
            .await
            .unwrap();
        if let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_millis(500), allocation.recv_from(&mut buf)).await
        {
            assert_eq!(from, peer);
            assert_eq!(&buf[..n], b"through the relay");
            echoed = true;
            break;
        }
    }
    assert!(echoed, "no echo through the TURN relay");

    allocation.close().await.unwrap();
    client.close().await.unwrap();
    relay.close().await;
}

#[tokio::test]
async fn turn_refuses_wrong_credentials() {
    let Some(h) = common::start().await else {
        return;
    };
    let node = node(&h, "rusty-turn-auth").await;
    let relay = TurnRelay::start(node.udp_binder().unwrap()).await.unwrap();
    let server = relay.info().urls[0]
        .trim_start_matches("turn:")
        .trim_end_matches("?transport=udp")
        .to_owned();
    let client = Client::new(ClientConfig {
        stun_serv_addr: server.clone(),
        turn_serv_addr: server,
        username: relay.info().username.clone(),
        password: "wrong".into(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        vnet: None,
    })
    .await
    .unwrap();
    client.listen().await.unwrap();
    assert!(client.allocate().await.is_err());
    client.close().await.unwrap();
}

#[tokio::test]
async fn tcp_forward_reaches_the_peer() {
    let Some(h) = common::start().await else {
        return;
    };
    let node = node(&h, "rusty-forward").await;
    let forward = node.forward_tcp(&h.ready.peer_name, 80).await.unwrap();
    assert!(forward.local_addr().ip().is_loopback());

    // Two connections, one after the other, through the same forward.
    for _ in 0..2 {
        let mut stream = tokio::net::TcpStream::connect(forward.local_addr())
            .await
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.ends_with("hello from peer"), "{response}");
    }
    assert!(node.forward_tcp("nobody", 80).await.is_err());
}
