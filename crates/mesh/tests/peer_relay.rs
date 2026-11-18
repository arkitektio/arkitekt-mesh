//! Peer relays against tailscale's own: a tsnet node relays UDP
//! (`net/udprelay`), tailscale's test control grants its use, and the
//! tsnet peer speaks the client side as magicsock does. Our node takes no
//! direct path (as the tsnet nodes do not), so the peer is reached through
//! the relay or through DERP.

mod common;

use std::time::{Duration, Instant};

use mesh::driver::{Config, Limits, Node, PeerPath};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(h: &common::Harness, name: &str, peer_relay: bool) -> Config {
    Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: name.into(),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits: Limits {
            never_direct: true,
            peer_relay,
            ..Limits::default()
        },
    }
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

/// `size` bytes to the echo at `host:port` and back, the same.
async fn echo(node: &Node, host: &str, port: u16, size: usize) {
    let stream = node.dial(host, port).await.unwrap();
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

/// Keep talking to `host` until the path to it is `wanted`, or panic with
/// what it was instead.
async fn path_becomes(node: &Node, host: &str, wanted: impl Fn(&PeerPath) -> bool) -> PeerPath {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        // Traffic keeps the peer in use: an idle one is not looked for.
        let _ = get(node, host).await;
        let path = node.path(host).unwrap();
        if wanted(&path) {
            return path;
        }
        assert!(
            Instant::now() < deadline,
            "the path to {host} stayed {path:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Our node and a tsnet peer, no direct path: both bind to the tsnet relay,
/// and TCP flows through it.
#[tokio::test]
async fn a_tailscale_peer_is_reached_through_a_tailscale_relay() {
    common::init_tracing();
    let Some(h) = common::start_with_relay().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-relayed", true))
        .await
        .unwrap();
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));

    let path = path_becomes(&node, &h.ready.peer_name, |p| {
        matches!(p, PeerPath::PeerRelay(_))
    })
    .await;
    let PeerPath::PeerRelay(relay) = path else {
        unreachable!()
    };
    assert_eq!(relay.port(), h.ready.relay_port, "the relay's own port");
    assert_eq!(
        node.direct_path(h.ready.peer_ip.parse().unwrap()),
        None,
        "a relay path is not a direct one"
    );

    // A megabyte each way through the relay, and the path holds.
    echo(&node, &h.ready.peer_name, 7, 1 << 20).await;
    assert!(get(&node, &h.ready.peer_name)
        .await
        .ends_with("hello from peer"));
    assert!(matches!(
        node.path(&h.ready.peer_name).unwrap(),
        PeerPath::PeerRelay(_)
    ));
}

/// Our node as the relay, tailscale's own clients as its users: the second
/// tsnet node reaches the first through the port our node relays on.
#[tokio::test]
async fn tailscale_clients_meet_on_our_relay() {
    common::init_tracing();
    let Some(mut h) = common::start_for_a_relay().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-relay", true)).await.unwrap();
    let relay = node.serve_peer_relay(0, vec![]).await.unwrap();
    assert_ne!(relay.port(), 0);
    assert!(!relay.addrs().is_empty(), "it knows where it is");

    let deadline = Instant::now() + Duration::from_secs(60);
    let through = format!(":{}:vni:", relay.port());
    loop {
        let ping = h.ping().await;
        let via = ping["peer_relay"].as_str().unwrap_or_default().to_owned();
        if via.contains(&through) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "tailscale's clients did not take our relay: {ping}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // One endpoint, both of them bound to it, their pings forwarded.
    let sessions = relay.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert!(sessions[0].bound.iter().all(Option::is_some));
    assert!(sessions[0].packets.iter().all(|n| *n > 0), "{sessions:?}");

    // Gone with its handle: no more endpoints, and the port is free again.
    let port = relay.port();
    drop(relay);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(tokio::net::UdpSocket::bind(("0.0.0.0", port)).await.is_ok());
}

/// Three of our own nodes: one relays, the other two, with no direct path,
/// meet on it and carry a megabyte each way.
#[tokio::test]
async fn our_nodes_meet_on_our_relay() {
    common::init_tracing();
    let Some(h) = common::start_for_a_relay().await else {
        return;
    };
    let middle = Node::start(config(&h, "rusty-middle", true)).await.unwrap();
    let relay = middle.serve_peer_relay(0, vec![]).await.unwrap();
    let server = Node::start(config(&h, "rusty-listens", true))
        .await
        .unwrap();
    let client = Node::start(config(&h, "rusty-dials", true)).await.unwrap();
    let mut listener = server.listen(7).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    let host = server.addresses()[0].to_string();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if client.netmap().peer_by_ip(server.addresses()[0]).is_some() {
            echo(&client, &host, 7, 4096).await;
            if let PeerPath::PeerRelay(at) = client.path(&host).unwrap() {
                assert_eq!(at.port(), relay.port());
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no path through our relay: {:?}",
            client.path(&host)
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let before: u64 = relay.sessions().iter().flat_map(|s| s.bytes).sum();
    echo(&client, &host, 7, 1 << 20).await;
    let after: u64 = relay.sessions().iter().flat_map(|s| s.bytes).sum();
    assert!(
        after - before > 2 << 20,
        "the megabyte each way went through the relay: {} bytes",
        after - before
    );
    // The relay's own ping says so too.
    let (_, path) = client.ping(&host).await.unwrap();
    assert!(matches!(path, PeerPath::PeerRelay(_)), "{path:?}");
}

/// With peer relays off the same node stays on DERP, and the tsnet peer's
/// call-me-maybe-via is left unanswered.
#[tokio::test]
async fn with_peer_relays_off_derp_carries() {
    common::init_tracing();
    let Some(h) = common::start_with_relay().await else {
        return;
    };
    let node = Node::start(config(&h, "rusty-derp", false)).await.unwrap();
    let until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < until {
        assert!(get(&node, &h.ready.peer_name)
            .await
            .ends_with("hello from peer"));
        let path = node.path(&h.ready.peer_name).unwrap();
        assert!(matches!(path, PeerPath::Relay { .. }), "{path:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Two of our own nodes through the tsnet relay: each allocates, each binds,
/// and a connection one accepts from the other goes through it.
#[tokio::test]
async fn two_of_our_nodes_meet_on_a_tailscale_relay() {
    common::init_tracing();
    let Some(h) = common::start_with_relay().await else {
        return;
    };
    let server = Node::start(config(&h, "rusty-listens", true))
        .await
        .unwrap();
    let client = Node::start(config(&h, "rusty-dials", true)).await.unwrap();
    let mut listener = server.listen(7).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    let host = server.addresses()[0].to_string();
    // The client learns of the server from control a moment after it joins.
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if client.netmap().peer_by_ip(server.addresses()[0]).is_some() {
            echo(&client, &host, 7, 4096).await;
            if matches!(client.path(&host).unwrap(), PeerPath::PeerRelay(_)) {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no relay path between our nodes: {:?}",
            client.path(&host)
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    echo(&client, &host, 7, 1 << 20).await;
    let PeerPath::PeerRelay(relay) = client.path(&host).unwrap() else {
        panic!("left the relay: {:?}", client.path(&host));
    };
    assert_eq!(relay.port(), h.ready.relay_port);
    // And the server, the other way.
    let back = client.addresses()[0].to_string();
    assert!(
        matches!(server.path(&back).unwrap(), PeerPath::PeerRelay(_)),
        "{:?}",
        server.path(&back)
    );
}
