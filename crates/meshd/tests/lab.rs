//! `arkitekt-meshd` against the local mesh lab (our ionskale fork and a
//! tsnet peer); skipped unless `eval "$(testing/mesh-lab/lab.sh env)"`.

use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn meshd_proxies_relays_and_forwards_over_ionskale() {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(url), Some(key), Some(peer)) = (
        var("ARKITEKT_TEST_MESH_URL"),
        var("ARKITEKT_TEST_MESH_KEY"),
        var("ARKITEKT_TEST_MESH_PEER"),
    ) else {
        eprintln!("skipping: the mesh lab is not up (testing/mesh-lab/lab.sh up)");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // ARKITEKT_MESH_CA_FILE (from lab.sh env) is inherited: DERP trusts the lab CA.
    let mut child = Command::new(env!("CARGO_BIN_EXE_arkitekt-meshd"))
        .arg(format!("--statedir={}", dir.path().join("node").display()))
        .arg(format!("--hostname=t-meshd-{}", std::process::id()))
        .arg(format!("--control-url={url}"))
        .arg("--turn")
        .arg(format!("--forward=web={peer}:80"))
        .env("ARKITEKT_MESH_AUTHKEY", key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(90),
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line),
    )
    .await
    .expect("meshd reported in time")
    .unwrap();
    let ready: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["event"], "ready", "{ready}");
    assert!(ready["turn"]["urls"][0]
        .as_str()
        .unwrap()
        .starts_with("turn:127.0.0.1:"));

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(ready["proxy"].as_str().unwrap()).unwrap())
        .build()
        .unwrap();
    let forward = format!("http://{}/", ready["forwards"]["web"].as_str().unwrap());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let through_proxy = client.get(format!("http://{peer}/")).send().await;
        let through_forward = reqwest::get(&forward).await;
        if let (Ok(a), Ok(b)) = (through_proxy, through_forward) {
            assert_eq!(a.text().await.unwrap(), "hello from peer");
            assert_eq!(b.text().await.unwrap(), "hello from peer");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer never answered"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
