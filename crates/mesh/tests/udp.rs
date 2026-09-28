//! UDP over the mesh against the Go tsnet peer's UDP echo (:7), over DERP
//! and over a direct path.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use mesh::driver::{Config, Node, UdpSocket};
use mesh::keys::NodeIdentity;

fn config(h: &common::Harness, name: &str, direct: bool) -> Config {
    Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: name.into(),
        ephemeral: true,
        tags: vec![],
        direct,
        limits: Default::default(),
    }
}

/// Send `payload` to the echo until it comes back (the first datagrams can
/// race the WireGuard handshake and DERP setup).
async fn echo(socket: &UdpSocket, peer: SocketAddr, payload: &[u8]) {
    let mut buf = [0u8; 2048];
    for _ in 0..40 {
        socket.send_to(payload, peer).await.unwrap();
        if let Ok(got) =
            tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await
        {
            let (n, from) = got.unwrap();
            assert_eq!(from, peer);
            assert_eq!(&buf[..n], payload);
            return;
        }
    }
    panic!("no UDP echo from {peer}");
}

async fn round_trips(direct: bool, name: &str) {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, name, direct)).await.unwrap();
    let peer: SocketAddr = format!("{}:7", h.ready.peer_ip).parse().unwrap();
    let socket = node.bind_udp(0).unwrap();
    assert!(node.addresses().contains(&socket.local_addr().ip()));

    echo(&socket, peer, b"ping").await;
    if direct {
        // UDP traffic alone keeps path discovery going until it is direct.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while node.direct_path(peer.ip()).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "no direct path within 30 s"
            );
            echo(&socket, peer, b"keepalive").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    // Datagrams up to the largest that fits the tunnel.
    let big = vec![0x5a; mesh::netstack::MAX_UDP_PAYLOAD];
    echo(&socket, peer, &big).await;
    // Many in a row.
    for i in 0..200u32 {
        echo(&socket, peer, &i.to_be_bytes()).await;
    }
    assert_eq!(node.direct_path(peer.ip()).is_some(), direct);
}

#[tokio::test]
async fn udp_over_derp() {
    round_trips(false, "rusty-udp-derp").await;
}

#[tokio::test]
async fn udp_over_a_direct_path() {
    round_trips(true, "rusty-udp-direct").await;
}

#[tokio::test]
async fn udp_refuses_what_is_not_a_peer() {
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-udp-refuse", false))
        .await
        .unwrap();
    let socket = node.bind_udp(0).unwrap();
    let err = socket
        .send_to(b"x", "8.8.8.8:53".parse().unwrap())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    let too_big = vec![0; mesh::netstack::MAX_UDP_PAYLOAD + 1];
    let peer: SocketAddr = format!("{}:7", h.ready.peer_ip).parse().unwrap();
    assert_eq!(
        socket.send_to(&too_big, peer).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
