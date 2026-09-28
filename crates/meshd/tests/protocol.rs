//! The meshd protocol end to end against tailscale's test control server
//! and a tsnet peer (the Go harness from `crates/mesh`; skipped without Go).

#[path = "../../mesh/tests/common/mod.rs"]
mod common;

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

struct Meshd {
    child: Child,
    event: Value,
}

async fn meshd(dir: &Path, key: Option<&str>, args: &[&str]) -> Meshd {
    let mut command = Command::new(env!("CARGO_BIN_EXE_arkitekt-meshd"));
    command
        .arg(format!("--statedir={}", dir.display()))
        .arg("--hostname=meshd-test")
        .args(args)
        .env_remove("ARKITEKT_MESH_AUTHKEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(key) = key {
        command.env("ARKITEKT_MESH_AUTHKEY", key);
    }
    let mut child = command.spawn().unwrap();
    let mut line = String::new();
    let stdout = child.stdout.as_mut().unwrap();
    tokio::time::timeout(
        Duration::from_secs(60),
        BufReader::new(stdout).read_line(&mut line),
    )
    .await
    .expect("meshd reported in time")
    .unwrap();
    let event = serde_json::from_str(&line).unwrap_or(Value::Null);
    Meshd { child, event }
}

fn control(h: &common::Harness) -> String {
    format!("--control-url={}", h.ready.control_url)
}

#[tokio::test]
async fn without_a_key_it_needs_a_login() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = meshd(dir.path(), None, &["--control-url=http://127.0.0.1:1"]).await;
    assert_eq!(m.event["event"], "error");
    assert_eq!(m.event["code"], "needs_login");
    assert!(!m.child.wait().await.unwrap().success());
}

#[tokio::test]
async fn usage_errors_are_reported_too() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_arkitekt-meshd"))
        .arg("--hostname=x")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .await
        .unwrap();
    let event: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(event["code"], "usage");
    assert!(!child.wait().await.unwrap().success());
}

#[tokio::test]
async fn joins_proxies_relays_and_forwards() {
    let Some(h) = common::start_with(true).await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let node = dir.path().join("node");
    let forward = format!("--forward=web={}:80", h.ready.peer_name);
    let mut m = meshd(
        &node,
        Some(&h.ready.auth_key),
        &[&control(&h), "--turn", &forward],
    )
    .await;
    assert_eq!(m.event["event"], "ready", "{}", m.event);
    let proxy = m.event["proxy"].as_str().unwrap().to_owned();
    assert!(proxy.starts_with("http://127.0.0.1:"));
    assert!(m.event["ips"].as_array().is_some_and(|ips| !ips.is_empty()));
    let turn = &m.event["turn"];
    assert!(turn["urls"][0]
        .as_str()
        .unwrap()
        .starts_with("turn:127.0.0.1:"));
    assert!(turn["username"].is_string() && turn["credential"].is_string());

    // The proxy reaches the peer by name.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy).unwrap())
        .build()
        .unwrap();
    let url = format!("http://{}/", h.ready.peer_name);
    let body = client.get(&url).send().await.unwrap().text().await.unwrap();
    assert_eq!(body, "hello from peer");

    // So does the forward, as a plain local port.
    let web = m.event["forwards"]["web"].as_str().unwrap();
    let body = reqwest::get(format!("http://{web}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "hello from peer");

    // One node per directory.
    let second = meshd(&node, Some(&h.ready.auth_key), &[&control(&h)]).await;
    assert_eq!(second.event["code"], "locked", "{}", second.event);

    // Closing stdin stops it, cleanly.
    m.child.stdin.take().unwrap().shutdown().await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), m.child.wait())
        .await
        .expect("meshd stops when stdin closes")
        .unwrap();
    assert!(status.success(), "{status}");

    // The joined node restarts with neither key nor control url.
    let again = meshd(&node, None, &[]).await;
    assert_eq!(again.event["event"], "ready", "{}", again.event);
}
