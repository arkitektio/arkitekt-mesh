//! Port mapping over PCP (docs/rfc3-nat-port-mapping.md), against a fake
//! NAT gateway that really forwards: the node maps its port, reports the
//! mapping as an endpoint, keeps it renewed, maps again after the gateway
//! restarts, and deletes it when it goes away.
//! (A test binary of its own: the gateway is chosen by an environment variable.)
// The fake NAT's external side is 127.0.0.2, which only Linux answers
// without configuration.
#![cfg(target_os = "linux")]

mod common;
mod fake_nat;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use fake_nat::{Gateway, Speaks};
use mesh::driver::{Config, Node};
use mesh::keys::NodeIdentity;

fn config(h: &common::Harness, name: &str) -> Config {
    Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: name.into(),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits: Default::default(),
    }
}

async fn until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_mapping_is_reported_renewed_remapped_and_deleted() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    // Two-second mappings: renewals every second.
    let gateway = Gateway::start(Speaks::Pcp, 2).await;
    std::env::set_var(mesh::driver::portmap::GATEWAY_ENV, gateway.addr.to_string());

    let a_identity = NodeIdentity::generate();
    let a_key = a_identity.node_public();
    let mut a_config = config(&h, "rusty-mapped");
    a_config.identity = a_identity;
    let a = Node::start(a_config).await.unwrap();
    // B maps nothing (it shares the process, so the gateway, with A).
    let mut b_config = config(&h, "rusty-outside");
    b_config.limits.portmap = false;
    let b = Node::start(b_config).await.unwrap();

    // A maps its port, and B learns the mapped address as one of A's
    // endpoints (through control)...
    until("no mapping", 10, || !gateway.externals().is_empty()).await;
    let mapped = gateway.externals()[0];
    let b_sees = |addr| {
        b.netmap()
            .peer_by_key(&a_key)
            .is_some_and(|p| p.endpoints.contains(&addr))
    };
    until("B never saw the mapped endpoint", 30, || b_sees(mapped)).await;
    // ...and once B talks to A, its disco pings come in through the NAT
    // (disco probes only peers with traffic).
    let a_ip = a.addresses()[0].to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    while gateway.counters.forwarded.load(Ordering::Relaxed) == 0 {
        assert!(
            Instant::now() < deadline,
            "nothing came through the mapping"
        );
        let _ = tokio::time::timeout(Duration::from_millis(500), b.dial(&a_ip, 80)).await;
    }

    // Renewed at half the lifetime.
    let before = gateway.counters.maps.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert!(
        gateway.counters.maps.load(Ordering::Relaxed) >= before + 2,
        "no renewals"
    );

    // The gateway restarts and forgets: the next renewal maps a new port,
    // which A reports instead.
    gateway.reboot();
    until("A never mapped again", 10, || {
        !gateway.externals().is_empty()
    })
    .await;
    let remapped = gateway.externals()[0];
    assert_ne!(remapped, mapped);
    until("B never saw the new mapping", 30, || b_sees(remapped)).await;

    // Deleted (best effort) when A goes away.
    drop(a);
    until("no delete when the node stopped", 5, || {
        gateway.counters.deletes.load(Ordering::Relaxed) > 0
    })
    .await;
}
