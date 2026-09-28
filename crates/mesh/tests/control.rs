//! Stage 1: the control plane against tailscale's own test control server.

mod common;

use mesh::control::netmap::NetMap;
use mesh::control::types::*;
use mesh::driver::control::ControlClient;
use mesh::keys::{DiscoPublic, NodeIdentity, NodePublic, PrivateKey};

fn hostinfo(name: &str) -> Hostinfo {
    Hostinfo {
        hostname: name.into(),
        os: std::env::consts::OS.into(),
        ipn_version: "arkitekt-mesh-test".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn register_and_fetch_the_netmap() {
    common::init_tracing();
    let Some(h) = common::start().await else {
        return;
    };
    let id = NodeIdentity::generate();
    let disco = DiscoPublic(PrivateKey::generate().public());

    let client = ControlClient::connect(&h.ready.control_url, &id.machine.0)
        .await
        .unwrap();
    let resp = client
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            auth: Some(RegisterAuth {
                auth_key: h.ready.auth_key.clone(),
            }),
            hostinfo: hostinfo("rusty"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(resp.error.is_empty(), "{}", resp.error);
    assert!(resp.auth_url.is_empty());

    // The update that carries our disco key, then the stream.
    let mut update = client
        .map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            disco_key: disco,
            omit_peers: true,
            hostinfo: hostinfo("rusty"),
            ..Default::default()
        })
        .await
        .unwrap();
    while update.next().await.unwrap().is_some() {}

    let mut stream = client
        .map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            disco_key: disco,
            stream: true,
            keep_alive: true,
            hostinfo: hostinfo("rusty"),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut netmap = NetMap::default();
    netmap.apply(stream.next().await.unwrap().expect("a first map response"));

    let me = netmap.self_node.as_ref().expect("self node");
    assert_eq!(me.key, id.node_public());
    assert!(!netmap.self_addresses().is_empty());
    let peer = netmap
        .peer_by_name(&h.ready.peer_name)
        .expect("the peer is in the netmap");
    assert_eq!(peer.addresses[0].to_string(), h.ready.peer_ip);
    assert_ne!(peer.key, NodePublic::default());
    assert!(!peer.disco_key.0.is_zero());
    assert!(
        !netmap.derp_regions.is_empty(),
        "the harness serves a DERP map"
    );
}

#[tokio::test]
async fn a_wrong_auth_key_is_refused() {
    let Some(h) = common::start().await else {
        return;
    };
    let id = NodeIdentity::generate();
    let client = ControlClient::connect(&h.ready.control_url, &id.machine.0)
        .await
        .unwrap();
    let resp = client
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: id.node_public(),
            auth: Some(RegisterAuth {
                auth_key: "tskey-wrong".into(),
            }),
            hostinfo: hostinfo("intruder"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!resp.error.is_empty());
}

/// A client that is dropped closes its connection, even with nothing sent:
/// a failed start must not leave connections (and memory) behind.
#[tokio::test]
async fn dropping_a_client_closes_its_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let Some(h) = common::start().await else {
        return;
    };
    // A proxy in front of control that reports when the client side closes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = h.ready.control_url.trim_start_matches("http://").to_owned();
    let (closed_tx, mut closed_rx) = tokio::sync::mpsc::channel::<()>(16);
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut server = TcpStream::connect(&upstream).await.unwrap();
            let closed = closed_tx.clone();
            tokio::spawn(async move {
                let (mut cr, mut cw) = client.split();
                let (mut sr, mut sw) = server.split();
                let up = async {
                    let mut buf = [0u8; 4096];
                    loop {
                        match cr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sw.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                };
                let down = tokio::io::copy(&mut sr, &mut cw);
                tokio::select! { _ = up => {}, _ = down => {} }
                let _ = closed.send(()).await;
            });
        }
    });

    let id = NodeIdentity::generate();
    let client = ControlClient::connect(&proxy_url, &id.machine.0)
        .await
        .unwrap();
    // `/key` was fetched on its own connection, which is closed already.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx.recv()).await;
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx.recv())
        .await
        .expect("the dropped client's connection closes")
        .unwrap();
}
