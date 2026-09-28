//! The mesh client against our ionskale fork and a tsnet peer (the local
//! mesh lab; see tests/mesh_lab/mod.rs for how to bring it up).

mod mesh_lab;
use mesh_lab as lab;

use std::sync::Arc;
use std::time::{Duration, Instant};

use lab::{eventually, get, lab};
use mesh::driver::Node;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn joins_and_reaches_the_peer_by_name_ip_and_fqdn() {
    lab::init_tracing();
    let Some(lab) = lab() else { return };
    let node = Node::start(lab.config(&lab.hostname("join"), true))
        .await
        .unwrap();

    eventually(30, "HTTP to the peer by name", || get(&node, &lab.peer)).await;
    get(&node, &lab.peer_ip).await.unwrap();
    // The FQDN the netmap carries (no MagicDNS: names come from the netmap).
    let fqdn = node
        .netmap()
        .peers()
        .iter()
        .find(|p| p.hostname() == lab.peer)
        .map(|p| p.name.trim_end_matches('.').to_owned())
        .expect("the peer is in the netmap");
    get(&node, &fqdn).await.unwrap();
}

#[tokio::test]
async fn tcp_echo_of_a_megabyte() {
    let Some(lab) = lab() else { return };
    let node = Node::start(lab.config(&lab.hostname("echo"), true))
        .await
        .unwrap();
    let stream = eventually(30, "dial the echo", || node.dial(&lab.peer, 7)).await;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let data: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr
    });
    let mut got = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(60), rd.read_exact(&mut got))
        .await
        .expect("the echo finished in time")
        .unwrap();
    assert!(got == expected, "the echo came back different");
    let _ = writer.await;
}

async fn udp_round_trips(direct: bool, what: &str) {
    let Some(lab) = lab() else { return };
    let node = Node::start(lab.config(&lab.hostname(what), direct))
        .await
        .unwrap();
    let socket = node.bind_udp(0).unwrap();
    let peer = lab.peer_udp();
    for payload in [&b"ping"[..], &vec![0x5a; mesh::netstack::MAX_UDP_PAYLOAD]] {
        eventually(30, "UDP echo", || async {
            let mut buf = [0u8; 2048];
            socket.send_to(payload, peer).await?;
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
                    .await
                    .map_err(|_| std::io::Error::other("no echo yet"))??;
            if from == peer && &buf[..n] == payload {
                Ok(())
            } else {
                Err(std::io::Error::other("a different datagram came back"))
            }
        })
        .await;
    }
    if direct {
        // Host and container reach each other: disco should find a path.
        let deadline = Instant::now() + Duration::from_secs(30);
        while node.direct_path(peer.ip()).is_none() {
            assert!(Instant::now() < deadline, "no direct path within 30 s");
            let _ = get(&node, &lab.peer).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    } else {
        assert_eq!(node.direct_path(peer.ip()), None, "DERP only");
    }
}

#[tokio::test]
async fn udp_over_ionskales_derp() {
    udp_round_trips(false, "udp-derp").await;
}

#[tokio::test]
async fn udp_over_a_direct_path() {
    udp_round_trips(true, "udp-direct").await;
}

#[tokio::test]
async fn nodes_see_each_other_join() {
    let Some(lab) = lab() else { return };
    let a = Node::start(lab.config(&lab.hostname("a"), true))
        .await
        .unwrap();
    let b_name = lab.hostname("b");
    let b = Node::start(lab.config(&b_name, true)).await.unwrap();
    let b_ip = b.addresses()[0];
    // A learns of B from a netmap delta, then reaches it... B serves nothing,
    // so a refused connection (not a timeout) proves the path.
    let deadline = Instant::now() + Duration::from_secs(30);
    while a.netmap().peer_by_ip(b_ip).is_none() {
        assert!(Instant::now() < deadline, "A never saw B join");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(a.resolve(&b_name).is_ok());
}

#[cfg(feature = "relay")]
#[tokio::test]
async fn turn_relays_to_the_peer_over_ionskale() {
    use mesh::driver::TurnRelay;
    use turn::client::{Client, ClientConfig};
    use webrtc_util::Conn;

    let Some(lab) = lab() else { return };
    let node = Arc::new(
        Node::start(lab.config(&lab.hostname("turn"), true))
            .await
            .unwrap(),
    );
    let relay = TurnRelay::start(node.udp_binder().unwrap()).await.unwrap();
    let info = relay.info().clone();
    let server = info.urls[0]
        .trim_start_matches("turn:")
        .trim_end_matches("?transport=udp")
        .to_owned();
    let client = Client::new(ClientConfig {
        stun_serv_addr: server.clone(),
        turn_serv_addr: server,
        username: info.username.clone(),
        password: info.credential.clone(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        vnet: None,
    })
    .await
    .unwrap();
    client.listen().await.unwrap();
    let allocation = client.allocate().await.unwrap();
    let peer = lab.peer_udp();
    eventually(30, "an echo through the relay", || async {
        let mut buf = [0u8; 1500];
        allocation
            .send_to(b"relayed", peer)
            .await
            .map_err(std::io::Error::other)?;
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(1), allocation.recv_from(&mut buf))
                .await
                .map_err(|_| std::io::Error::other("no echo yet"))?
                .map_err(std::io::Error::other)?;
        assert_eq!((from, &buf[..n]), (peer, &b"relayed"[..]));
        Ok(())
    })
    .await;
    client.close().await.unwrap();
    relay.close().await;
}

#[cfg(feature = "session")]
#[tokio::test]
async fn a_session_rejoins_without_key_or_url() {
    use mesh::driver::{Session, SessionOptions};

    let Some(lab) = lab() else { return };
    let dir = tempfile::tempdir().unwrap();
    let name = lab.hostname("session");
    let mut options = SessionOptions::new(dir.path().join("node"), name.clone());
    options.control_url = Some(lab.url.clone());
    options.auth_key = Some(lab.key.clone());
    let mut session = Session::start(options).await.unwrap();
    let proxy = session.serve_proxy("127.0.0.1:0").await.unwrap();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy).unwrap())
        .build()
        .unwrap();
    let url = format!("http://{}/", lab.peer);
    let body = eventually(30, "the proxy reaches the peer", || async {
        client
            .get(&url)
            .send()
            .await
            .map_err(std::io::Error::other)?
            .text()
            .await
            .map_err(std::io::Error::other)
    })
    .await;
    assert_eq!(body, "hello from peer");
    drop(session);

    // ionskale knows the node key: no auth key, no control url.
    let session = Session::start(SessionOptions::new(dir.path().join("node"), name))
        .await
        .unwrap();
    eventually(30, "HTTP after the restart", || {
        get(session.node(), &lab.peer)
    })
    .await;
}
