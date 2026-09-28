//! Disruptive checks against the mesh lab: restarting ionskale (control and
//! its DERP go away and come back) and expiring a node's key. A test binary
//! of their own, so they never overlap the other lab tests.

mod mesh_lab;
use mesh_lab as lab;

use std::time::{Duration, Instant};

use lab::{eventually, get, lab};
use mesh::driver::{Node, Session, SessionError, SessionOptions};

/// A restart would break the other test mid-way: one at a time (a tokio
/// mutex: each test has its own runtime, and the guard spans awaits).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn a_node_survives_a_control_restart() {
    lab::init_tracing();
    let Some(lab) = lab() else { return };
    let _serial = SERIAL.lock().await;
    let a = Node::start(lab.config(&lab.hostname("survivor"), false))
        .await
        .unwrap();
    eventually(30, "HTTP before the restart", || get(&a, &lab.peer)).await;

    lab.admin(&["restart"]);

    // DERP reconnects: the peer is reachable again.
    eventually(90, "HTTP after the restart", || get(&a, &lab.peer)).await;
    // The map stream reconnects: a node that joins now is seen.
    let b = Node::start(lab.config(&lab.hostname("late"), false))
        .await
        .unwrap();
    let b_ip = b.addresses()[0];
    let deadline = Instant::now() + Duration::from_secs(60);
    while a.netmap().peer_by_ip(b_ip).is_none() {
        assert!(
            Instant::now() < deadline,
            "no netmap updates after the restart"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn an_expired_node_asks_for_a_login_then_rejoins_with_a_key() {
    let Some(lab) = lab() else { return };
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let statedir = dir.path().join("node");
    let name = lab.hostname("expire");
    let options = |key: Option<&str>| {
        let mut o = SessionOptions::new(statedir.clone(), name.clone());
        o.control_url = Some(lab.url.clone());
        o.auth_key = key.map(str::to_owned);
        o.timeout = Duration::from_secs(60);
        o
    };
    drop(Session::start(options(Some(&lab.key))).await.unwrap());

    lab.admin(&["expire", &name]);

    let err = Session::start(options(None)).await.unwrap_err();
    assert!(matches!(err, SessionError::NeedsLogin), "{err}");
    // The dead node key was replaced; a key registers the new one.
    let session = Session::start(options(Some(&lab.key))).await.unwrap();
    eventually(30, "HTTP after rejoining", || {
        get(session.node(), &lab.peer)
    })
    .await;
}
