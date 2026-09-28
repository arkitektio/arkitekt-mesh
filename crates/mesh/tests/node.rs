//! Stages 2–3: a whole node against a Go tsnet peer, over DERP and direct.

mod common;

use std::time::{Duration, Instant};

use mesh::driver::{Config, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

async fn try_get(node: &Node, host: &str) -> std::io::Result<String> {
    let mut stream = node.dial(host, 80).await?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

async fn get(node: &Node, host: &str) -> String {
    let mut stream = node.dial(host, 80).await.unwrap();
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

async fn echo(node: &Node, host: &str, size: usize) {
    let stream = node.dial(host, 7).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr
    });
    let mut got = vec![0u8; size];
    rd.read_exact(&mut got).await.unwrap();
    assert!(got == expected, "the echo came back different");
    let _ = writer.await;
}

#[tokio::test]
async fn derp_only_http_and_echo() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-derp", false)).await.unwrap();

    let response = get(&node, &h.ready.peer_name).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("hello from peer"), "{response}");

    // By IP and FQDN too.
    let fqdn = format!("{}.{}", h.ready.peer_name, h.ready.domain);
    assert!(get(&node, &h.ready.peer_ip)
        .await
        .ends_with("hello from peer"));
    assert!(get(&node, &fqdn).await.ends_with("hello from peer"));

    echo(&node, &h.ready.peer_name, 1 << 20).await;
    assert_eq!(
        node.direct_path(h.ready.peer_ip.parse().unwrap()),
        None,
        "DERP only"
    );
}

#[tokio::test]
async fn direct_path_comes_up() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-direct", true)).await.unwrap();
    let peer_ip = h.ready.peer_ip.parse().unwrap();

    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));
    let deadline = Instant::now() + Duration::from_secs(30);
    while node.direct_path(peer_ip).is_none() {
        assert!(Instant::now() < deadline, "no direct path within 30 s");
        // Traffic keeps the path discovery going.
        let _ = get(&node, &h.ready.peer_name).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tracing::info!("direct path: {:?}", node.direct_path(peer_ip));
    let t = Instant::now();
    echo(&node, &h.ready.peer_name, 4 << 20).await;
    tracing::info!("4 MiB echo took {:?}", t.elapsed());
    assert!(node.direct_path(peer_ip).is_some());
}

#[tokio::test]
async fn unknown_hosts_fail_fast() {
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-unknown", false))
        .await
        .unwrap();
    let err = node.dial("nowhere", 80).await.err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn a_joined_node_restarts_without_its_key() {
    // Open control: re-registering a known node key needs no auth key (ionscale).
    let Some(h) = common::start_with(true).await else {
        return;
    };
    let first = config(&h, "rusty-restart", true);
    let node = Node::start(first.clone()).await.unwrap();
    let addresses = node.addresses().to_vec();
    drop(node);

    let again = Config {
        auth_key: None,
        ..first
    };
    let node = Node::start(again).await.unwrap();
    assert_eq!(node.addresses(), addresses, "same identity, same addresses");
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));
}

/// Control, DERP and the peer all restart (DERP on a new port): a DERP-only
/// node re-registers, reconnects DERP to where the new map says, and
/// reaches the new peer.
#[tokio::test]
async fn survives_a_restart_of_control_and_derp() {
    common::init_tracing();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let Some(h) = common::start_full(false, 0, Some(port)).await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-restarts", false))
        .await
        .unwrap();
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));

    drop(h); // kills control, DERP and the peer
    tokio::time::sleep(Duration::from_secs(1)).await;
    let h = common::start_full(false, 0, Some(port)).await.unwrap();

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let attempt =
            tokio::time::timeout(Duration::from_secs(10), try_get(&node, &h.ready.peer_name)).await;
        if matches!(&attempt, Ok(Ok(body)) if body.ends_with("hello from peer")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no contact after the restart: {attempt:?}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Past `max_active_peers`, the least recently used peers lose their tunnel
/// state, but the priority peer keeps it (and keeps working).
#[tokio::test]
async fn the_active_peer_cap_spares_the_priority_peer() {
    common::init_tracing();
    let Some(h) = common::start_opts(false, 10).await else {
        return;
    };
    let mut cfg = config(&h, "rusty-capped", false);
    cfg.limits.max_active_peers = 3;
    let node = Node::start(cfg).await.unwrap();
    node.set_priority_peer(&h.ready.peer_name).unwrap();
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));
    assert!(node.is_active(&h.ready.peer_name));

    // Offline peers: each dial makes tunnel state (a handshake that never
    // completes), pushing the real peer to least recently used.
    let fakes: Vec<String> = node
        .netmap()
        .peers()
        .iter()
        .filter(|p| p.hostname().starts_with("fake-peer"))
        .map(|p| p.primary_address().unwrap().to_string())
        .collect();
    assert_eq!(fakes.len(), 10);
    for fake in &fakes {
        let _ = tokio::time::timeout(Duration::from_millis(200), node.dial(fake, 80)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(node.active_peers() <= 3, "{} active", node.active_peers());
    assert!(
        node.is_active(&h.ready.peer_name),
        "the priority peer was evicted"
    );
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));
}

/// A rebind mid-connection: the stream keeps working (WireGuard sessions
/// survive), and a direct path comes back on the new socket.
#[tokio::test]
async fn rebind_keeps_connections_and_finds_a_new_path() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-rebind", true)).await.unwrap();
    let peer_ip = h.ready.peer_ip.parse().unwrap();

    let mut stream = node.dial(&h.ready.peer_name, 7).await.unwrap();
    echo_round(&mut stream, b"before").await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while node.direct_path(peer_ip).is_none() {
        assert!(
            Instant::now() < deadline,
            "no direct path before the rebind"
        );
        echo_round(&mut stream, b"warming").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let old = node.direct_path(peer_ip);
    let old_port = node.udp_port();

    node.rebind();
    echo_round(&mut stream, b"during").await; // over DERP while paths are rediscovered
    assert_ne!(node.udp_port(), old_port, "rebind took a new UDP socket");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        echo_round(&mut stream, b"after").await;
        if node.direct_path(peer_ip).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no direct path after the rebind (was {old:?})"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn echo_round(stream: &mut mesh::driver::TcpStream, msg: &[u8]) {
    stream.write_all(msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut back))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(back, msg);
}

/// Two of our nodes: one listens, the other dials it by name, twice (a
/// listener re-arms after each accept); a port nobody listens on refuses.
#[tokio::test]
async fn nodes_accept_connections() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let server = Node::start(config(&h, "rusty-server", true)).await.unwrap();
    let client = Node::start(config(&h, "rusty-client", true)).await.unwrap();

    let mut listener = server.listen(8080).unwrap();
    let serving = tokio::spawn(async move {
        for i in 0..2 {
            let (mut stream, from) = listener.accept().await.unwrap();
            let mut name = String::new();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            name.push_str(std::str::from_utf8(&buf[..n]).unwrap());
            stream
                .write_all(format!("hello {name} #{i} from {from}").as_bytes())
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    // The client's netmap learns about the server asynchronously.
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.resolve("rusty-server").is_err() {
        assert!(Instant::now() < deadline, "the server never showed up");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    for i in 0..2 {
        let mut stream = client.dial("rusty-server", 8080).await.unwrap();
        stream.write_all(b"client").await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        let client_ip = client.addresses()[0];
        assert!(
            reply.starts_with(&format!("hello client #{i} from {client_ip}:")),
            "{reply}"
        );
    }
    serving.await.unwrap();

    let refused = client.dial("rusty-server", 9999).await.err().unwrap();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
}
