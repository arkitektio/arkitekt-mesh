//! The tailnet's ACLs, enforced by our node (docs/rfc8-packet-filter.md),
//! against ionskale's own packet filters: the mesh lab's `lab-acl` tailnet
//! has lok's shape (`tag:app` may reach `tag:hub` on port 80; the hub never
//! initiates). Both ends are our nodes, so each check is our filter's doing.

mod mesh_lab;

use std::net::SocketAddr;
use std::time::Duration;

use mesh::driver::{Config, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn keys() -> Option<(String, String, String)> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let Some(keys) = (|| {
        Some((
            var("ARKITEKT_TEST_MESH_URL")?,
            var("ARKITEKT_TEST_MESH_ACL_APP_KEY")?,
            var("ARKITEKT_TEST_MESH_ACL_HUB_KEY")?,
        ))
    })() else {
        eprintln!("skipping: the mesh lab is not up (testing/mesh-lab/lab.sh up)");
        return None;
    };
    Some(keys)
}

async fn node(url: &str, key: &str, name: &str) -> Node {
    Node::start(Config {
        control_url: url.into(),
        identity: NodeIdentity::generate(),
        auth_key: Some(key.into()),
        hostname: format!("t-acl-{name}-{}", std::process::id()),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits: Default::default(),
    })
    .await
    .unwrap()
}

/// Whether `from` gets a TCP connection to `to:port` answered within 5 s.
async fn connects(from: &Node, to: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            from.dial(&to.ip().to_string(), to.port())
        )
        .await,
        Ok(Ok(_))
    )
}

#[tokio::test]
async fn the_hub_accepts_the_app_on_80_only_and_never_initiates() {
    mesh_lab::init_tracing();
    let Some((url, app_key, hub_key)) = keys() else {
        return;
    };
    let hub = node(&url, &hub_key, "hub").await;
    let app = node(&url, &app_key, "app").await;
    let (hub_ip, app_ip) = (hub.addresses()[0], app.addresses()[0]);

    // Both listen on 80 and 81.
    let mut hub_80 = hub.listen(80).unwrap();
    let _hub_81 = hub.listen(81).unwrap();
    let _app_80 = app.listen(80).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = hub_80.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"hub").await;
            });
        }
    });

    // Allowed: app -> hub:80, once the peers see each other.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        if let Ok(Ok(s)) =
            tokio::time::timeout(Duration::from_secs(5), app.dial(&hub_ip.to_string(), 80)).await
        {
            break s;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "app never reached hub:80"
        );
    };
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hub");

    // Denied: another port on the hub, and the hub initiating at all.
    let dropped_before = hub.filtered_packets();
    assert!(
        !connects(&app, SocketAddr::new(hub_ip, 81)).await,
        "app reached hub:81"
    );
    assert!(
        hub.filtered_packets() > dropped_before,
        "the hub's filter dropped the SYNs"
    );
    let app_dropped_before = app.filtered_packets();
    assert!(
        !connects(&hub, SocketAddr::new(app_ip, 80)).await,
        "the hub initiated"
    );
    assert!(
        app.filtered_packets() > app_dropped_before,
        "the app's filter dropped the SYNs"
    );
}

#[tokio::test]
async fn udp_replies_pass_but_unsolicited_datagrams_do_not() {
    let Some((url, app_key, hub_key)) = keys() else {
        return;
    };
    let hub = node(&url, &hub_key, "udp-hub").await;
    let app = node(&url, &app_key, "udp-app").await;
    let hub_socket = hub.bind_udp(80).unwrap();
    let app_socket = app.bind_udp(0).unwrap();
    let to_hub = SocketAddr::new(hub.addresses()[0], 80);

    // app -> hub:80 is allowed; the hub's reply is a reply, so it passes the
    // app's filter although no rule lets the hub in.
    let mut buf = [0u8; 64];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let from = loop {
        app_socket.send_to(b"ping", to_hub).await.unwrap();
        if let Ok(Ok((_, from))) =
            tokio::time::timeout(Duration::from_millis(500), hub_socket.recv_from(&mut buf)).await
        {
            break from;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub never heard the app"
        );
    };
    hub_socket.send_to(b"pong", from).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), app_socket.recv_from(&mut buf))
        .await
        .expect("the reply came back")
        .unwrap();
    assert_eq!(&buf[..n], b"pong");

    // Unsolicited: the hub to another port of the app is dropped.
    let other = app.bind_udp(0).unwrap();
    hub_socket
        .send_to(b"hello?", other.local_addr())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), other.recv_from(&mut buf))
            .await
            .is_err(),
        "an unsolicited datagram got through"
    );
}
