//! Tailnet lock against our ionskale fork (docs/rfc5-tailnet-lock.md): the
//! mesh lab's `lab-lock` tailnet, locked by a real tailscaled (`lab.sh
//! lock`), whose trusted key signs node keys (`lab.sh lock-sign`).

mod mesh_lab;

use std::time::{Duration, Instant};

use mesh::driver::{Config, LockStatus, Node, Session, SessionError, SessionOptions};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Env {
    lab: mesh_lab::Lab,
    key: String,
}

fn env() -> Option<Env> {
    let lab = mesh_lab::lab()?;
    let Some(key) = std::env::var("ARKITEKT_TEST_MESH_LOCK_KEY")
        .ok()
        .filter(|k| !k.is_empty())
    else {
        eprintln!("skipping: the lab's tailnet lock is not set up (testing/mesh-lab/lab.sh lock)");
        return None;
    };
    Some(Env { lab, key })
}

fn config(env: &Env, identity: NodeIdentity, what: &str) -> Config {
    let mut config = env.lab.config(&env.lab.hostname(what), true);
    config.identity = identity;
    config.auth_key = Some(env.key.clone());
    config
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

async fn until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn a_session_is_refused_until_signed_then_rejoins() {
    mesh_lab::init_tracing();
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let statedir = dir.path().join("node");
    let name = env.lab.hostname("lock-session");
    let options = |key: Option<&str>| {
        let mut o = SessionOptions::new(statedir.clone(), name.clone());
        o.control_url = Some(env.lab.url.clone());
        o.auth_key = key.map(str::to_owned);
        o.ephemeral = true;
        o
    };
    let err = Session::start(options(Some(&env.key))).await.unwrap_err();
    let SessionError::LockedOut(nodekey) = &err else {
        panic!("{err}")
    };
    assert!(statedir.join("tka.json").is_file());

    // The real admin signs; the node restarts with neither key nor url, on
    // the chain it saved.
    env.lab.admin(&["lock-sign", nodekey]);
    let deadline = Instant::now() + Duration::from_secs(30);
    let session = loop {
        match Session::start(options(None)).await {
            Ok(s) => break s,
            Err(SessionError::LockedOut(_)) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            Err(e) => panic!("{e}"),
        }
    };
    let LockStatus::Locked {
        trusted_keys,
        locked_out,
        ..
    } = session.node().lock_status()
    else {
        panic!("not locked: {:?}", session.node().lock_status());
    };
    assert_eq!((trusted_keys, locked_out), (1, false));
}

#[tokio::test]
async fn signed_nodes_reach_each_other_and_unsigned_ones_stay_hidden() {
    let Some(env) = env() else { return };
    let (a_id, b_id) = (NodeIdentity::generate(), NodeIdentity::generate());
    let (a_key, b_key) = (a_id.node_public(), b_id.node_public());
    let a = Node::start(config(&env, a_id, "lock-a")).await.unwrap();
    let b = Node::start(config(&env, b_id, "lock-b")).await.unwrap();
    let stranger = Node::start(config(&env, NodeIdentity::generate(), "lock-stranger"))
        .await
        .unwrap();
    assert!(locked_out(&a) && locked_out(&b) && locked_out(&stranger));

    env.lab.admin(&["lock-sign", &a_key.text()]);
    env.lab.admin(&["lock-sign", &b_key.text()]);
    until("a and b never saw their signatures", || {
        !locked_out(&a) && !locked_out(&b)
    })
    .await;

    // b serves; a (signed, sees b signed) connects.
    let mut listener = b.listen(80).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let _ = s.write_all(b"signed").await;
        }
    });
    let b_ip = b.addresses()[0];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Ok(mut s)) =
            tokio::time::timeout(Duration::from_secs(5), a.dial(&b_ip.to_string(), 80)).await
        {
            let mut got = [0u8; 6];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"signed");
            break;
        }
        assert!(Instant::now() < deadline, "a never reached b");
    }

    // The stranger is hidden from both, and cannot reach them.
    let stranger_ip = stranger.addresses()[0];
    until("a still sees the stranger", || {
        a.netmap().peer_by_ip(stranger_ip).is_none()
    })
    .await;
    assert!(b.netmap().peer_by_ip(stranger_ip).is_none());
    assert!(
        matches!(a.lock_status(), LockStatus::Locked { hidden_peers, .. } if hidden_peers >= 1)
    );
    let dial =
        tokio::time::timeout(Duration::from_secs(5), stranger.dial(&b_ip.to_string(), 80)).await;
    assert!(
        !matches!(dial, Ok(Ok(_))),
        "an unsigned node reached a signed one"
    );
}
