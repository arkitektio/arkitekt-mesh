//! Join a mesh and fetch `http://HOST:PORT/PATH` from a peer, printing the
//! response: a quick way to reach a device (e.g. the ESP32's `/status`).
//!
//! ```sh
//! eval "$(testing/mesh-lab/lab.sh env)"          # URL, key, CA for the lab
//! cargo run -p arkitekt-mesh --example probe -- esp32-mesh 80 /
//! ```
//!
//! Reads `ARKITEKT_TEST_MESH_URL` and `ARKITEKT_TEST_MESH_KEY`; extra CA
//! roots come from `ARKITEKT_MESH_CA_FILE` (as everywhere in the crate).

use std::time::{Duration, Instant};

use mesh::driver::{Config, Limits, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh=info".into()),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or("usage: probe HOST [PORT] [PATH]")?;
    let port: u16 = args.next().map(|p| p.parse()).transpose()?.unwrap_or(80);
    let path = args.next().unwrap_or_else(|| "/".into());

    let node = Node::start(Config {
        control_url: std::env::var("ARKITEKT_TEST_MESH_URL")?,
        identity: NodeIdentity::generate(),
        auth_key: std::env::var("ARKITEKT_TEST_MESH_KEY").ok(),
        hostname: "mesh-probe".into(),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits: Limits::default(),
    })
    .await?;

    // A peer that just joined may not be in our first netmap yet.
    let deadline = Instant::now() + Duration::from_secs(30);
    while node.resolve(&host).is_err() {
        if Instant::now() > deadline {
            return Err(format!("{host} is not on the mesh").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let started = Instant::now();
    let mut stream = node.dial(&host, port).await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    eprintln!("({} bytes in {:?})", response.len(), started.elapsed());
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}
