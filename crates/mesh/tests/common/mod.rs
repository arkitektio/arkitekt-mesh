//! Starts the Go harness (tests/harness): tailscale's test control server,
//! DERP/STUN and a tsnet peer. Tests are skipped when `go` is missing.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

#[derive(Debug, Clone, Deserialize)]
pub struct Ready {
    pub control_url: String,
    pub auth_key: String,
    pub peer_name: String,
    pub peer_ip: String,
    pub domain: String,
}

pub struct Harness {
    pub ready: Ready,
    _child: Child,
    _stdin: ChildStdin,
}

/// Build the harness binary once per test run.
fn binary() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        // Also used from other crates' tests (fakts), next to this one.
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let Some(dir) = [
            manifest.join("tests/harness"),
            manifest.join("../mesh/tests/harness"),
        ]
        .into_iter()
        .find(|d| d.join("harness_test.go").is_file()) else {
            // Not shipped in the published crate.
            eprintln!("skipping: the Go harness is not here");
            return None;
        };
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mesh-harness");
        let status = std::process::Command::new("go")
            .args(["test", "-c", "-o"])
            .arg(&out)
            .arg(".")
            .current_dir(dir)
            .status();
        match status {
            Ok(s) if s.success() => Some(out),
            Ok(s) => panic!("building the Go harness failed: {s}"),
            Err(e) => {
                eprintln!("skipping: go is not available ({e})");
                None
            }
        }
    })
    .clone()
}

/// Start a fresh tailnet. `None` (skip the test) without Go.
pub async fn start() -> Option<Harness> {
    start_with(false).await
}

/// With `open`, control takes registrations without an auth key.
pub async fn start_with(open: bool) -> Option<Harness> {
    start_opts(open, 0).await
}

/// `fake_peers` offline peers are added to the netmap.
pub async fn start_opts(open: bool, fake_peers: usize) -> Option<Harness> {
    start_full(open, fake_peers, None).await
}

/// With `control_port`, control listens there (so it can be restarted at
/// the same URL).
pub async fn start_full(
    open: bool,
    fake_peers: usize,
    control_port: Option<u16>,
) -> Option<Harness> {
    start_env(open, fake_peers, control_port, &[]).await
}

/// A locked tailnet (tailnet lock); sign node keys with [`Harness::sign`].
pub async fn start_locked() -> Option<Harness> {
    start_env(false, 0, None, &[("MESH_HARNESS_LOCK", "1")]).await
}

/// Everything (control, DERP, STUN, the peer) on `::1` only.
pub async fn start_ipv6() -> Option<Harness> {
    start_env(false, 0, None, &[("MESH_HARNESS_ADDR", "::1")]).await
}

/// Two DERP regions; region 1's STUN answers nothing.
pub async fn start_two_regions() -> Option<Harness> {
    start_env(false, 0, None, &[("MESH_HARNESS_TWO_REGIONS", "1")]).await
}

async fn start_env(
    open: bool,
    fake_peers: usize,
    control_port: Option<u16>,
    env: &[(&str, &str)],
) -> Option<Harness> {
    let bin = binary()?;
    let mut command = Command::new(bin);
    command.envs(env.iter().copied());
    if let Some(port) = control_port {
        command.env("MESH_HARNESS_CONTROL_PORT", port.to_string());
    }
    if open {
        command.env("MESH_HARNESS_OPEN", "1");
    }
    if fake_peers > 0 {
        command.env("MESH_HARNESS_FAKE_PEERS", fake_peers.to_string());
    }
    let mut child = command
        .args(["-test.run", "TestHarness"])
        .env("MESH_HARNESS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if std::env::var_os("MESH_HARNESS_VERBOSE").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .kill_on_drop(true)
        .spawn()
        .expect("start the harness");
    let stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if line.starts_with('{') {
                return serde_json::from_str::<Ready>(&line).unwrap();
            }
        }
        panic!("the harness exited before it was ready");
    })
    .await
    .expect("the harness did not start in time");
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    Some(Harness {
        ready,
        _child: child,
        _stdin: stdin,
    })
}

impl Harness {
    /// Sign `node_key` with the lock's trusted key (a locked harness; the
    /// node must have registered).
    pub async fn sign(&mut self, node_key: &mesh::keys::NodePublic) {
        use tokio::io::AsyncWriteExt;
        self._stdin
            .write_all(format!("sign {}\n", node_key.text()).as_bytes())
            .await
            .unwrap();
        self._stdin.flush().await.unwrap();
    }
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh=debug".into()),
        )
        .with_test_writer()
        .try_init();
}
