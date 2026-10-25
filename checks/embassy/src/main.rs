//! The embassy driver against a real control server, on the host:
//!
//! ```sh
//! cargo run -- harness   # the Go harness (needs go), as CI runs it
//! cargo run -- lab       # the mesh lab's ionskale: eval "$(testing/mesh-lab/lab.sh env)"
//! cargo run -- harness --derp-only   # no direct paths: everything through DERP
//! ```
//!
//! The node joins, then reaches the peer over the tunnel: HTTP on :80 (or
//! the lab peer's), and 64 KiB through the harness peer's TCP echo on :7.

mod host;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embedded_io_async::{Read, Write};
use mesh_core::keys::PrivateKey;
use mesh_embassy::{Config, Mesh};

/// What to join and whom to reach there.
struct Target {
    control_url: String,
    auth_key: String,
    peer: String,
    peer_ip: String,
    /// The harness peer echoes TCP on :7; the lab's does not.
    echo: bool,
    _harness: Option<Child>,
}

#[derive(serde::Deserialize)]
struct Ready {
    control_url: String,
    auth_key: String,
    peer_name: String,
    peer_ip: String,
}

/// Build and start the Go harness, until it prints where it is.
fn harness() -> Target {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/mesh/tests/harness"
    );
    let bin = concat!(env!("CARGO_MANIFEST_DIR"), "/target/mesh-harness");
    let built = Command::new("go")
        .args(["test", "-c", "-o", bin, "."])
        .current_dir(dir)
        .status()
        .expect("go");
    assert!(built.success(), "building the Go harness failed");
    let mut child = Command::new(bin)
        .args(["-test.run", "TestHarness"])
        .env("MESH_HARNESS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if std::env::var_os("MESH_HARNESS_VERBOSE").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
        .expect("start the harness");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready: Ready = loop {
        let line = lines.next().expect("the harness exited").unwrap();
        if line.starts_with('{') {
            break serde_json::from_str(&line).unwrap();
        }
    };
    std::thread::spawn(move || for _ in lines {});
    Target {
        control_url: ready.control_url,
        auth_key: ready.auth_key,
        peer: ready.peer_name,
        peer_ip: ready.peer_ip,
        echo: true,
        _harness: Some(child),
    }
}

fn lab() -> Target {
    let var =
        |n: &str| std::env::var(n).unwrap_or_else(|_| panic!("{n}: load the lab's environment"));
    Target {
        control_url: var("ARKITEKT_TEST_MESH_URL"),
        auth_key: var("ARKITEKT_TEST_MESH_KEY"),
        peer: var("ARKITEKT_TEST_MESH_PEER"),
        peer_ip: var("ARKITEKT_TEST_MESH_PEER_IP"),
        echo: false,
        _harness: None,
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        if let Some(child) = &mut self._harness {
            let _ = child.kill();
        }
    }
}

async fn http_get(mesh: &Mesh, host: &str) -> String {
    let ip = mesh
        .resolve(host)
        .unwrap_or_else(|| panic!("{host} is not in the netmap"));
    let mut stream = mesh.connect((ip, 80).into()).await.expect("connect :80");
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
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
    String::from_utf8_lossy(&response).into_owned()
}

async fn echo(mesh: &Mesh, ip: &str, size: usize) {
    let ip = ip.parse().unwrap();
    let mut stream = mesh
        .connect(std::net::SocketAddr::new(ip, 7))
        .await
        .expect("connect :7");
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut back = Vec::with_capacity(size);
    let mut buf = vec![0u8; 4096];
    let mut sent = 0;
    while back.len() < size {
        if sent < size {
            let n = stream
                .write(&data[sent..(sent + 4096).min(size)])
                .await
                .unwrap();
            sent += n;
        }
        // Read what has come back meanwhile (the echo keeps pace).
        match embassy_time::with_timeout(
            embassy_time::Duration::from_millis(50),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => panic!("the echo closed"),
            Ok(Ok(n)) => back.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read: {e}"),
            Err(_) => {}
        }
    }
    assert!(back == data, "the echo came back different");
}

/// A direct UDP path to the peer comes up (unless DERP only).
async fn direct(mesh: &Mesh, peer_ip: &str) {
    let ip = peer_ip.parse().unwrap();
    for _ in 0..100 {
        if let Some(path) = mesh.direct_path(ip) {
            println!("direct path to {peer_ip}: {path}");
            return;
        }
        embassy_time::Timer::after_millis(100).await;
    }
    panic!("no direct path to {peer_ip} within 10 s");
}

async fn scenario(mesh: &Mesh, target: &Target, derp_only: bool) {
    mesh.joined().await;
    println!("joined as {:?}", mesh.addresses());
    let response = http_get(mesh, &target.peer).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    println!(
        "GET http://{}/ over the tunnel: {}",
        target.peer,
        response.lines().next().unwrap_or("")
    );
    if target.echo {
        echo(mesh, &target.peer_ip, 64 << 10).await;
        println!("64 KiB through the peer's echo");
    }
    if derp_only {
        assert_eq!(
            mesh.direct_path(target.peer_ip.parse().unwrap()),
            None,
            "DERP only"
        );
    } else {
        direct(mesh, &target.peer_ip).await;
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh_embassy=debug".into()),
        )
        .try_init();
    let target = match std::env::args().nth(1).as_deref() {
        Some("harness") | None => harness(),
        Some("lab") => lab(),
        Some(other) => panic!("unknown target {other}: harness or lab"),
    };
    let mut config = Config::small(
        target.control_url.clone(),
        PrivateKey::generate(),
        PrivateKey::generate(),
    );
    config.auth_key = Some(target.auth_key.clone());
    config.hostname = format!("embassy-check-{}", std::process::id());
    config.ephemeral = true;
    let derp_only = std::env::args().any(|a| a == "--derp-only");
    config.settings.direct = !derp_only;
    println!(
        "{}",
        if derp_only {
            "DERP only"
        } else {
            "direct paths allowed"
        }
    );
    let mesh = Mesh::new(config);
    let udp = host::HostUdp::bind();
    let dial = host::HostDial::new();

    let run = async {
        match select(mesh.run(&udp, &dial), scenario(&mesh, &target, derp_only)).await {
            Either::First(result) => panic!("the node ended: {result:?}"),
            Either::Second(()) => {}
        }
    };
    if embassy_time::with_timeout(embassy_time::Duration::from_secs(60), run)
        .await
        .is_err()
    {
        eprintln!("FAILED: timed out");
        std::process::exit(1);
    }
    println!("ok");
    drop(target);
    std::thread::sleep(Duration::from_millis(10));
    std::process::exit(0);
}
