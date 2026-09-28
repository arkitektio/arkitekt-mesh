//! Choosing the home DERP region by measured latency
//! (docs/rfc4-derp-home-by-latency.md), against two regions of which the
//! lower-numbered one does not answer STUN.

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
        direct: false,
        limits,
    }
}

async fn wait_home(node: &Node, want: i32) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while node.home_region() != Some(want) {
        assert!(
            Instant::now() < deadline,
            "home is {:?}, not {want}",
            node.home_region()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn the_node_homes_to_the_region_that_answers() {
    common::init_tracing();
    let Some(h) = common::start_two_regions().await else {
        return;
    };
    // Starts on the lowest id (1), measures, moves to 2.
    let node = Node::start(config(&h, "rusty-netcheck", Limits::default()))
        .await
        .unwrap();
    wait_home(&node, 2).await;

    // And the peer is still reachable over DERP, wherever it is homed.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Ok(mut s)) =
            tokio::time::timeout(Duration::from_secs(5), node.dial(&h.ready.peer_name, 80)).await
        {
            s.write_all(b"GET / HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut r = String::new();
            s.read_to_string(&mut r).await.unwrap();
            assert!(r.ends_with("hello from peer"), "{r}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the peer was not reachable after re-homing"
        );
    }
}

#[tokio::test]
async fn small_nodes_measure_once_too() {
    let Some(h) = common::start_two_regions().await else {
        return;
    };
    // `Limits::small()` has no periodic netcheck, but still the one at start.
    let node = Node::start(config(&h, "rusty-netcheck-small", Limits::small()))
        .await
        .unwrap();
    wait_home(&node, 2).await;
}
