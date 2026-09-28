//! The local mesh lab (testing/mesh-lab): our ionskale fork and a tsnet
//! peer. Tests using it skip unless the lab's environment is loaded:
//!
//! ```sh
//! testing/mesh-lab/lab.sh up
//! eval "$(testing/mesh-lab/lab.sh env)"
//! cargo test -p arkitekt-mesh --features session,relay --test lab --test lab_restart
//! ```

#![allow(dead_code)]

use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use mesh::driver::{Config, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Lab {
    pub url: String,
    pub key: String,
    pub peer: String,
    pub peer_ip: String,
    script: Option<String>,
}

/// The lab, if its environment is loaded.
pub fn lab() -> Option<Lab> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(url), Some(key), Some(peer), Some(peer_ip)) = (
        var("ARKITEKT_TEST_MESH_URL"),
        var("ARKITEKT_TEST_MESH_KEY"),
        var("ARKITEKT_TEST_MESH_PEER"),
        var("ARKITEKT_TEST_MESH_PEER_IP"),
    ) else {
        eprintln!(
            "skipping: the mesh lab is not up \
             (testing/mesh-lab/lab.sh up; eval \"$(testing/mesh-lab/lab.sh env)\")"
        );
        return None;
    };
    Some(Lab {
        url,
        key,
        peer,
        peer_ip,
        script: var("ARKITEKT_MESH_LAB"),
    })
}

impl Lab {
    /// A hostname no other test run uses (ionskale would rename a clash).
    pub fn hostname(&self, what: &str) -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            "t-{what}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    pub fn config(&self, hostname: &str, direct: bool) -> Config {
        Config {
            control_url: self.url.clone(),
            identity: NodeIdentity::generate(),
            auth_key: Some(self.key.clone()),
            hostname: hostname.into(),
            ephemeral: true,
            tags: vec![],
            direct,
            limits: Default::default(),
        }
    }

    pub fn peer_udp(&self) -> SocketAddr {
        format!("{}:7", self.peer_ip).parse().unwrap()
    }

    /// Run `lab.sh ARGS` (admin actions against ionskale).
    pub fn admin(&self, args: &[&str]) -> String {
        let script = self
            .script
            .as_deref()
            .expect("ARKITEKT_MESH_LAB (from lab.sh env) is needed for admin actions");
        let out = Command::new(script)
            .args(args)
            .output()
            .expect("run lab.sh");
        assert!(
            out.status.success(),
            "lab.sh {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Retry `f` for up to `secs` (paths and peers take a moment to settle).
pub async fn eventually<T, F, Fut>(secs: u64, what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout(Duration::from_secs(10), f()).await {
            Ok(Ok(v)) => return v,
            Ok(Err(e)) if tokio::time::Instant::now() >= deadline => panic!("{what}: {e}"),
            Err(_) if tokio::time::Instant::now() >= deadline => panic!("{what}: timed out"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

pub async fn get(node: &Node, host: &str) -> std::io::Result<String> {
    let mut stream = node.dial(host, 80).await?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    if response.ends_with("hello from peer") {
        Ok(response)
    } else {
        Err(std::io::Error::other(format!(
            "unexpected response: {response}"
        )))
    }
}
