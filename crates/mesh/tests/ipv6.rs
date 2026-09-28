//! The IPv6 underlay (docs/rfc2-ipv6-underlay.md): the harness on `::1`
//! only, and nodes that may not use IPv4 for direct paths.

mod common;

use std::time::{Duration, Instant};

use mesh::driver::{Config, Limits, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(h: &common::Harness, name: &str, limits: Limits) -> Config {
    Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: name.into(),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits,
    }
}

async fn get(node: &Node, host: &str) -> bool {
    let attempt = async {
        let mut s = node.dial(host, 80).await?;
        s.write_all(b"GET / HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n")
            .await?;
        let mut r = String::new();
        s.read_to_string(&mut r).await?;
        Ok::<_, std::io::Error>(r.ends_with("hello from peer"))
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), attempt).await,
        Ok(Ok(true))
    )
}

#[tokio::test]
async fn a_direct_path_comes_up_over_ipv6() {
    common::init_tracing();
    let Some(h) = common::start_ipv6().await else {
        return;
    };
    let limits = Limits {
        ipv4: false,
        ..Limits::default()
    };
    let node = Node::start(config(&h, "rusty-v6", limits)).await.unwrap();
    let peer_ip = h.ready.peer_ip.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let reached = get(&node, &h.ready.peer_name).await;
        if let Some(path) = node.direct_path(peer_ip) {
            assert!(path.is_ipv6(), "{path}");
            assert!(reached || get(&node, &h.ready.peer_name).await);
            return;
        }
        assert!(Instant::now() < deadline, "no direct IPv6 path within 30 s");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn without_ipv6_it_stays_on_derp() {
    common::init_tracing();
    let Some(h) = common::start_ipv6().await else {
        return;
    };
    // Neither family for direct paths: IPv4 is off, and ::1 is all there is.
    let limits = Limits {
        ipv4: false,
        ipv6: false,
        ..Limits::default()
    };
    let node = Node::start(config(&h, "rusty-v6-derp", limits))
        .await
        .unwrap();
    assert!(get(&node, &h.ready.peer_name).await || get(&node, &h.ready.peer_name).await);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(node.direct_path(h.ready.peer_ip.parse().unwrap()), None);
}
