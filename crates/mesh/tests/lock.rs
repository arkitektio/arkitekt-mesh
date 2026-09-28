//! Tailnet lock end to end (docs/rfc5-tailnet-lock.md): tailscale's test
//! control server with the lock initialized by the Go peer, which holds the
//! trusted key and signs node keys on request.

mod common;

use std::time::{Duration, Instant};

use mesh::driver::{Config, LockStatus, Node, Session, SessionError, SessionOptions};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(h: &common::Harness, identity: NodeIdentity, name: &str) -> Config {
    Config {
        control_url: h.ready.control_url.clone(),
        identity,
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: name.into(),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits: Default::default(),
    }
}

async fn reaches_peer(node: &Node, peer: &str) -> bool {
    let attempt = async {
        let mut s = node.dial(peer, 80).await?;
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

async fn until(what: &str, secs: u64, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !check() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn locked_out(node: &Node) -> bool {
    matches!(
        node.lock_status(),
        LockStatus::Locked {
            locked_out: true,
            ..
        }
    )
}

#[tokio::test]
async fn an_unsigned_node_is_locked_out_until_signed() {
    common::init_tracing();
    let Some(mut h) = common::start_locked().await else {
        return;
    };
    let identity = NodeIdentity::generate();
    let key = identity.node_public();
    let node = Node::start(config(&h, identity, "rusty-unsigned"))
        .await
        .unwrap();

    // It sees the lock (and trusts the signed peer), but is not signed itself:
    // the peer's own lock drops us, so nothing gets through.
    match node.lock_status() {
        LockStatus::Locked {
            locked_out,
            trusted_keys,
            ..
        } => {
            assert!(locked_out);
            assert_eq!(trusted_keys, 1);
        }
        other => panic!("not locked: {other:?}"),
    }
    assert!(
        node.resolve(&h.ready.peer_name).is_ok(),
        "the signed peer is trusted"
    );
    assert!(!reaches_peer(&node, &h.ready.peer_name).await);

    // Signed: control pushes the signature, and the peer accepts us.
    h.sign(&key).await;
    until("still locked out after signing", 20, || !locked_out(&node)).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !reaches_peer(&node, &h.ready.peer_name).await {
        assert!(
            Instant::now() < deadline,
            "signed, but the peer never answered"
        );
    }
}

#[tokio::test]
async fn unsigned_peers_are_hidden() {
    let Some(mut h) = common::start_locked().await else {
        return;
    };
    let a_identity = NodeIdentity::generate();
    let a_key = a_identity.node_public();
    let a = Node::start(config(&h, a_identity, "rusty-signed"))
        .await
        .unwrap();
    h.sign(&a_key).await;
    until("a never got signed", 20, || !locked_out(&a)).await;

    // B joins unsigned: A must not see it at all.
    let b = Node::start(config(&h, NodeIdentity::generate(), "rusty-stranger"))
        .await
        .unwrap();
    let b_ip = b.addresses()[0];
    until(
        "a never heard of b",
        20,
        || matches!(a.lock_status(), LockStatus::Locked { hidden_peers, .. } if hidden_peers >= 1),
    )
    .await;
    assert!(
        a.netmap().peer_by_ip(b_ip).is_none(),
        "an unsigned peer is visible"
    );
    assert!(a.resolve("rusty-stranger").is_err());
    assert!(a.dial(&b_ip.to_string(), 80).await.is_err());
}

#[tokio::test]
async fn a_session_refuses_to_start_locked_out_and_keeps_its_chain() {
    let Some(mut h) = common::start_locked().await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let statedir = dir.path().join("node");
    let (control_url, auth_key) = (h.ready.control_url.clone(), h.ready.auth_key.clone());
    let options = |key: bool| {
        let mut o = SessionOptions::new(statedir.clone(), "rusty-session");
        o.control_url = Some(control_url.clone());
        o.auth_key = key.then(|| auth_key.clone());
        o.ephemeral = false;
        o
    };
    let err = Session::start(options(true)).await.unwrap_err();
    let SessionError::LockedOut(ref key) = err else {
        panic!("{err}")
    };
    assert_eq!(err.code(), "locked_out");
    assert!(
        err.to_string().contains("tailscale lock sign nodekey:"),
        "{err}"
    );
    assert!(
        statedir.join("tka.json").is_file(),
        "the verified chain is kept"
    );

    // The operator signs the key it named; the next start works.
    let key = mesh::keys::NodePublic::parse(key).unwrap();
    h.sign(&key).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // (testcontrol wants the auth key on every registration; ionscale does not.)
    let session = Session::start(options(true)).await.unwrap();
    assert!(matches!(
        session.node().lock_status(),
        LockStatus::Locked {
            locked_out: false,
            ..
        }
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !reaches_peer(session.node(), &h.ready.peer_name).await {
        assert!(
            Instant::now() < deadline,
            "the signed session never reached the peer"
        );
    }
}
