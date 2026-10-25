//! The web driver under node: it joins (control by WebSocket), then
//! reaches the peer over the tunnel (DERP by WebSocket). run.sh gives the
//! target in the environment.

#![cfg(target_arch = "wasm32")]

use embedded_io_async::{Read, Write};
use mesh_core::keys::PrivateKey;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

/// `process.env[name]`.
fn env(name: &str) -> Option<String> {
    let process = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("process")).ok()?;
    let env = js_sys::Reflect::get(&process, &JsValue::from_str("env")).ok()?;
    js_sys::Reflect::get(&env, &JsValue::from_str(name))
        .ok()?
        .as_string()
}

#[wasm_bindgen_test]
async fn joins_and_reaches_the_peer_over_websockets() {
    let Some(url) = env("MESH_WEB_CONTROL_URL") else {
        // Not started by run.sh: nothing to join. run.sh says it must.
        assert!(env("MESH_WEB_REQUIRED").is_none(), "run.sh set no target");
        console_log!("skipping: no MESH_WEB_CONTROL_URL (run it with run.sh)");
        return;
    };
    console_log!("joining {url}");
    let peer = env("MESH_WEB_PEER").expect("MESH_WEB_PEER");
    let peer_ip: core::net::IpAddr = env("MESH_WEB_PEER_IP")
        .expect("MESH_WEB_PEER_IP")
        .parse()
        .unwrap();

    mesh_web::install();
    let mut config = mesh_web::config(url, PrivateKey::generate(), PrivateKey::generate());
    config.auth_key = env("MESH_WEB_AUTH_KEY");
    config.hostname = format!("web-check-{}", (js_sys::Math::random() * 1e6) as u32);
    config.ephemeral = true;
    let mesh = mesh_web::start(config);

    let test = async {
        mesh.joined().await;
        console_log!("joined as {:?}", mesh.addresses());
        let ip = mesh.resolve(&peer).expect("the peer is in the netmap");
        assert_eq!(ip, peer_ip);
        let mut stream = mesh.connect((ip, 80).into()).await.expect("connect :80");
        let request = format!("GET / HTTP/1.1\r\nHost: {peer}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e) => panic!("read: {e}"),
            }
        }
        let response = String::from_utf8_lossy(&response).into_owned();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        console_log!(
            "GET http://{peer}/ over the tunnel: {}",
            response.lines().next().unwrap_or("")
        );
        // A browser has no UDP: DERP carried it.
        assert_eq!(mesh.direct_path(ip), None);
    };
    embassy_time::with_timeout(embassy_time::Duration::from_secs(60), test)
        .await
        .expect("timed out");
}
