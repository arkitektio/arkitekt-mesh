//! Throughput, latency and start-up figures (docs/rfc7-production-and-throughput.md).
//! Nothing is asserted: the tables are printed, to compare before and after
//! a change.
//!
//! ```sh
//! cargo test -p arkitekt-mesh --release --features session --test bench -- --ignored --nocapture
//! ```
//!
//! `bench_harness` runs against the Go harness, both ends on this machine:
//! no round trip to speak of, so it shows what the CPU allows. `bench_lab`
//! needs the mesh lab (tests/mesh_lab/mod.rs) and shapes the peer's link
//! with `lab.sh netem`, which is where a TCP window shows.
//!
//! `MESH_BENCH_MIB` (64) bounds each transfer and `MESH_BENCH_SECS` (10) its
//! time, whichever comes first. To compare settings: `MESH_BENCH_TCP_KIB`
//! (the TCP buffer), `MESH_BENCH_CONGESTION` (`none`, `reno`, `cubic`),
//! `MESH_BENCH_DERP_BURST`, and
//! `MESH_BENCH_NETEM` and `MESH_BENCH_ROWS` (only the lab's link conditions,
//! and transfers, whose name holds it). `MESH_BENCH_PART` runs one part:
//! `tunnel`, `proxy` or `startup`.

mod common;
mod mesh_lab;

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http1::SendRequest;
use hyper::Request;
use hyper_util::rt::TokioIo;
use mesh::driver::{Config, Limits, Node, Session, SessionOptions};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type Body = BoxBody<Bytes, Infallible>;

const CHUNK: usize = 64 << 10;

/// A tailnet to join and the peer to talk to.
#[derive(Clone)]
struct Target {
    control_url: String,
    auth_key: String,
    peer: String,
    peer_ip: IpAddr,
}

impl Target {
    fn config(&self, hostname: &str, direct: bool) -> Config {
        Config {
            control_url: self.control_url.clone(),
            identity: NodeIdentity::generate(),
            auth_key: Some(self.auth_key.clone()),
            hostname: hostname.into(),
            ephemeral: true,
            tags: vec![],
            direct,
            limits: limits(),
        }
    }

    /// A node that reaches the peer, over a direct path if `direct`.
    async fn node(&self, hostname: &str, direct: bool) -> Arc<Node> {
        let node = Arc::new(Node::start(self.config(hostname, direct)).await.unwrap());
        settle(&node, self, direct).await;
        node
    }
}

/// Wait until the peer answers and, with `direct`, until the path is direct.
async fn settle(node: &Node, target: &Target, direct: bool) {
    mesh_lab::eventually(60, "HTTP to the peer", || mesh_lab::get(node, &target.peer)).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while direct && node.direct_path(target.peer_ip).is_none() {
        assert!(Instant::now() < deadline, "no direct path within 30 s");
        // Traffic keeps the path discovery going.
        let _ = mesh_lab::get(node, &target.peer).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The default limits, but for what the environment overrides.
fn limits() -> Limits {
    let mut limits = Limits::default();
    if let Ok(kib) = std::env::var("MESH_BENCH_TCP_KIB") {
        limits.tcp_buffer = kib.parse::<usize>().expect("MESH_BENCH_TCP_KIB") << 10;
    }
    if let Ok(burst) = std::env::var("MESH_BENCH_DERP_BURST") {
        limits.derp_burst = burst.parse().expect("MESH_BENCH_DERP_BURST");
    }
    if let Ok(name) = std::env::var("MESH_BENCH_CONGESTION") {
        limits.congestion = match name.as_str() {
            "none" => mesh::netstack::Congestion::None,
            "reno" => mesh::netstack::Congestion::Reno,
            "cubic" => mesh::netstack::Congestion::Cubic,
            other => panic!("MESH_BENCH_CONGESTION: {other}"),
        };
    }
    limits
}

/// Whether `MESH_BENCH_PART` (`tunnel`, `proxy`, `startup`) asks for `part`,
/// or for everything.
fn wanted(part: &str) -> bool {
    std::env::var("MESH_BENCH_PART").map_or(true, |only| only == part)
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn budget() -> (u64, Duration) {
    (
        env_or("MESH_BENCH_MIB", 64) << 20,
        Duration::from_secs(env_or("MESH_BENCH_SECS", 10)),
    )
}

/// This process's CPU time (user and system), on Linux.
fn cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // After the command name (which may hold spaces): state, then numbers.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let ticks: u64 = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    Some(ticks as f64 / 100.0)
}

async fn http<S>(io: S) -> SendRequest<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

fn empty() -> Body {
    Empty::new().boxed()
}

fn request(method: &str, uri: &str, host: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .body(body)
        .unwrap()
}

/// GET `uri`, reading up to the budget; the bytes read.
async fn download(sender: &mut SendRequest<Body>, uri: &str, host: &str) -> u64 {
    let (_, time) = budget();
    let deadline = Instant::now() + time;
    sender.ready().await.unwrap();
    let response = sender
        .send_request(request("GET", uri, host, empty()))
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let mut body = response.into_body();
    let mut read = 0u64;
    while Instant::now() < deadline {
        match body.frame().await {
            Some(frame) => read += frame.unwrap().data_ref().map_or(0, |d| d.len() as u64),
            None => break,
        }
    }
    read
}

/// POST up to the budget to `uri`; the bytes the peer says arrived.
async fn upload(sender: &mut SendRequest<Body>, uri: &str, host: &str) -> u64 {
    let (size, time) = budget();
    let deadline = Instant::now() + time;
    let chunk = Bytes::from(vec![0u8; CHUNK]);
    let stream = futures::stream::unfold(0u64, move |sent| {
        let chunk = chunk.clone();
        async move {
            (sent < size && Instant::now() < deadline)
                .then(|| (Ok::<_, Infallible>(Frame::data(chunk)), sent + CHUNK as u64))
        }
    });
    sender.ready().await.unwrap();
    let response = sender
        .send_request(request(
            "POST",
            uri,
            host,
            BodyExt::boxed(StreamBody::new(stream)),
        ))
        .await
        .unwrap();
    let text = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&text).trim().parse().unwrap()
}

#[derive(Clone, Copy)]
enum Direction {
    Down,
    Up,
}

/// One transfer per stream, each on a mesh connection of its own, at once.
async fn transfer(node: &Arc<Node>, target: &Target, direction: Direction, streams: usize) -> Rate {
    let (size, _) = budget();
    let cpu = cpu_seconds();
    let dropped = node.derp_dropped();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let (node, peer) = (node.clone(), target.peer.clone());
        tasks.push(tokio::spawn(async move {
            let mut sender = http(node.dial(&peer, 80).await.unwrap()).await;
            match direction {
                Direction::Down => download(&mut sender, &format!("/bytes?n={size}"), &peer).await,
                Direction::Up => upload(&mut sender, "/sink", &peer).await,
            }
        }));
    }
    // A stream that has not finished long after its time is up has stalled
    // (it counts for nothing, and the row says so).
    let (_, time) = budget();
    let (mut bytes, mut stalled) = (0, 0);
    for task in tasks {
        let abort = task.abort_handle();
        match tokio::time::timeout_at((started + 3 * time).into(), task).await {
            Ok(done) => bytes += done.unwrap(),
            Err(_) => {
                abort.abort();
                stalled += 1;
            }
        }
    }
    let mut rate = Rate::new(bytes, started.elapsed(), cpu);
    rate.stalled = stalled;
    rate.dropped = node.derp_dropped() - dropped;
    rate
}

struct Rate {
    bytes: u64,
    elapsed: Duration,
    cpu: Option<f64>,
    stalled: usize,
    /// Packets our DERP queue dropped meanwhile.
    dropped: u64,
}

impl Rate {
    fn new(bytes: u64, elapsed: Duration, cpu_before: Option<f64>) -> Self {
        Self {
            bytes,
            elapsed,
            cpu: cpu_before.zip(cpu_seconds()).map(|(a, b)| b - a),
            stalled: 0,
            dropped: 0,
        }
    }

    fn row(&self, label: &str) {
        let mib = self.bytes as f64 / (1 << 20) as f64;
        let secs = self.elapsed.as_secs_f64();
        let cpu = match self.cpu {
            Some(cpu) if mib > 0.0 => format!("{:6.2}", cpu / (mib / 1024.0)),
            _ => "     -".into(),
        };
        let mut label = label.to_owned();
        if self.stalled > 0 {
            label += &format!(", {} stalled", self.stalled);
        }
        if self.dropped > 0 {
            label += &format!(", {} dropped", self.dropped);
        }
        println!(
            "| {label:<44} | {:8.1} | {:8.1} | {:7.0} | {cpu} |",
            mib / secs,
            mib * 8.0 * 1.048576 / secs,
            mib,
        );
    }
}

fn rate_head(title: &str) {
    println!("\n### {title}\n");
    println!(
        "| {:<44} | {:>8} | {:>8} | {:>7} | {:>6} |",
        "transfer", "MiB/s", "Mbit/s", "MiB", "CPU s/GiB"
    );
    println!(
        "|{:-<46}|{:->10}|{:->10}|{:->9}|{:->8}|",
        "", "", "", "", ""
    );
}

/// The four transfers of a path: down and up, one stream and eight.
async fn transfers(target: &Target, hostname: &str, direct: bool) {
    let node = target.node(hostname, direct).await;
    let path = if direct { "direct" } else { "DERP" };
    for (direction, name) in [(Direction::Down, "download"), (Direction::Up, "upload")] {
        for streams in [1, 8] {
            transfer(&node, target, direction, streams)
                .await
                .row(&format!("{path} {name}, {streams} stream(s)"));
        }
    }
}

/// `CONNECT host:80` through the proxy; the tunnel.
async fn connect_tunnel(proxy: &str, host: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {host}:80 HTTP/1.1\r\nHost: {host}:80\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "the proxy refused the tunnel"
    );
    stream
}

fn latency_row(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize].as_secs_f64() * 1e3;
    let total: Duration = samples.iter().sum();
    println!(
        "| {label:<44} | {:8.2} | {:8.2} | {:8.2} | {:8.0} |",
        at(0.5),
        at(0.99),
        at(1.0),
        samples.len() as f64 / total.as_secs_f64(),
    );
}

async fn small_get(sender: &mut SendRequest<Body>, uri: &str, host: &str) {
    sender.ready().await.unwrap();
    let response = sender
        .send_request(request("GET", uri, host, empty()))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello from peer");
}

/// What a client pays per request through the local proxy, by how much of
/// the way it re-uses.
async fn proxy_rows(target: &Target, session: &Session) {
    let proxy = session.proxy_url().unwrap().trim_start_matches("http://");
    let peer = &target.peer;
    let absolute = format!("http://{peer}/");
    let requests = env_or("MESH_BENCH_REQUESTS", 500) as usize;

    println!("\n### Small GETs through the proxy ({requests} in a row)\n");
    println!(
        "| {:<44} | {:>8} | {:>8} | {:>8} | {:>8} |",
        "how the client connects", "p50 ms", "p99 ms", "max ms", "req/s"
    );
    println!(
        "|{:-<46}|{:->10}|{:->10}|{:->10}|{:->10}|",
        "", "", "", "", ""
    );

    let mut samples = Vec::new();
    for _ in 0..requests {
        let started = Instant::now();
        let mut sender = http(tokio::net::TcpStream::connect(proxy).await.unwrap()).await;
        small_get(&mut sender, &absolute, peer).await;
        samples.push(started.elapsed());
    }
    latency_row("http://, a proxy connection per request", samples);

    let mut sender = http(tokio::net::TcpStream::connect(proxy).await.unwrap()).await;
    let mut samples = Vec::new();
    for _ in 0..requests {
        let started = Instant::now();
        small_get(&mut sender, &absolute, peer).await;
        samples.push(started.elapsed());
    }
    latency_row("http://, one proxy connection kept", samples);

    let mut sender = http(connect_tunnel(proxy, peer).await).await;
    let mut samples = Vec::new();
    for _ in 0..requests {
        let started = Instant::now();
        small_get(&mut sender, "/", peer).await;
        samples.push(started.elapsed());
    }
    latency_row("CONNECT, one tunnel kept", samples);

    rate_head("Bulk through the proxy (direct path)");
    let (size, _) = budget();
    for (label, tunnel) in [("http://", false), ("CONNECT", true)] {
        let (mut sender, down, up) = if tunnel {
            let sender = http(connect_tunnel(proxy, peer).await).await;
            (sender, format!("/bytes?n={size}"), "/sink".to_owned())
        } else {
            let sender = http(tokio::net::TcpStream::connect(proxy).await.unwrap()).await;
            (
                sender,
                format!("http://{peer}/bytes?n={size}"),
                format!("http://{peer}/sink"),
            )
        };
        let (cpu, started) = (cpu_seconds(), Instant::now());
        let bytes = download(&mut sender, &down, peer).await;
        Rate::new(bytes, started.elapsed(), cpu).row(&format!("{label} download"));
        if bytes < size {
            // Cut short: the connection still holds the rest of the response.
            continue;
        }
        let (cpu, started) = (cpu_seconds(), Instant::now());
        let bytes = upload(&mut sender, &up, peer).await;
        Rate::new(bytes, started.elapsed(), cpu).row(&format!("{label} upload"));
    }

    // The shape of a chunked array: many objects of a few MiB, one after another.
    let (objects, object) = (32u64, 4u64 << 20);
    let mut sender = http(tokio::net::TcpStream::connect(proxy).await.unwrap()).await;
    let (cpu, started) = (cpu_seconds(), Instant::now());
    let mut bytes = 0;
    for _ in 0..objects {
        let uri = format!("http://{peer}/bytes?n={object}");
        sender.ready().await.unwrap();
        let response = sender
            .send_request(request("GET", &uri, peer, empty()))
            .await
            .unwrap();
        bytes += response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .len() as u64;
    }
    Rate::new(bytes, started.elapsed(), cpu).row("http://, 32 objects of 4 MiB in a row");
}

async fn session(target: &Target, statedir: &std::path::Path, hostname: &str) -> Session {
    let mut options = SessionOptions::new(statedir, hostname);
    options.limits = limits();
    options.control_url = Some(target.control_url.clone());
    options.auth_key = Some(target.auth_key.clone());
    let mut session = Session::start(options).await.unwrap();
    session.serve_proxy("127.0.0.1:0").await.unwrap();
    session
}

/// From nothing to the first answer from the peer, through the proxy.
async fn startup_rows(target: &Target, hostname: &str) {
    println!("\n### Start-up: `Session::start` to the first answer\n");
    println!(
        "| {:<28} | {:>10} | {:>14} | {:>10} |",
        "state directory", "on mesh ms", "first answer ms", "total ms"
    );
    println!("|{:-<30}|{:->12}|{:->16}|{:->12}|", "", "", "", "");
    let dir = tempfile::tempdir().unwrap();
    for label in ["empty (joins)", "joined before", "joined before"] {
        let started = Instant::now();
        let session = session(target, dir.path(), hostname).await;
        let joined = started.elapsed();
        let proxy = session.proxy_url().unwrap().trim_start_matches("http://");
        let absolute = format!("http://{}/", target.peer);
        // The first request may meet a path that is not up yet: retry, as
        // a client's alias probe would.
        loop {
            let io = tokio::net::TcpStream::connect(proxy).await.unwrap();
            let mut sender = http(io).await;
            let sent = sender
                .send_request(request("GET", &absolute, &target.peer, empty()))
                .await;
            if sent.is_ok_and(|r| r.status().is_success()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let total = started.elapsed();
        println!(
            "| {label:<28} | {:10.0} | {:14.0} | {:10.0} |",
            joined.as_secs_f64() * 1e3,
            (total - joined).as_secs_f64() * 1e3,
            total.as_secs_f64() * 1e3,
        );
        drop(session);
        // The lock on the state directory goes with the node's tasks.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a benchmark: run with --release -- --ignored --nocapture"]
async fn bench_harness() {
    // Quiet, unless asked: the tables are the output.
    if std::env::var_os("RUST_LOG").is_some() {
        mesh_lab::init_tracing();
    }
    let Some(h) = common::start().await else {
        return;
    };
    let target = Target {
        control_url: h.ready.control_url.clone(),
        auth_key: h.ready.auth_key.clone(),
        peer: h.ready.peer_name.clone(),
        peer_ip: h.ready.peer_ip.parse().unwrap(),
    };
    println!("\n## Go harness, both ends on this machine");

    if wanted("tunnel") {
        rate_head("Through the tunnel (`Node::dial`)");
        transfers(&target, "bench-direct", true).await;
        transfers(&target, "bench-derp", false).await;
    }
    if wanted("proxy") {
        let dir = tempfile::tempdir().unwrap();
        let session = session(&target, dir.path(), "bench-proxy").await;
        settle(session.node(), &target, true).await;
        proxy_rows(&target, &session).await;
    }
    if wanted("startup") {
        startup_rows(&target, "bench-start").await;
    }
}

/// Puts the peer's link back as it was, however the benchmark ends.
struct Netem<'a>(&'a mesh_lab::Lab);

impl Netem<'_> {
    fn set(&self, spec: &str) {
        let mut args = vec!["netem"];
        args.extend(spec.split_whitespace());
        self.0.admin(&args);
    }
}

impl Drop for Netem<'_> {
    fn drop(&mut self) {
        self.set("off");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a benchmark: run with --release -- --ignored --nocapture"]
async fn bench_lab() {
    // Quiet, unless asked: the tables are the output.
    if std::env::var_os("RUST_LOG").is_some() {
        mesh_lab::init_tracing();
    }
    let Some(lab) = mesh_lab::lab() else { return };
    let target = Target {
        control_url: lab.url.clone(),
        auth_key: lab.key.clone(),
        peer: lab.peer.clone(),
        peer_ip: lab.peer_ip.parse().unwrap(),
    };
    println!("\n## Mesh lab (ionskale, a tsnet peer in a container)");
    let Limits {
        tcp_buffer,
        congestion,
        ..
    } = limits();
    println!(
        "\nTCP buffer {} KiB, congestion control {congestion:?}",
        tcp_buffer >> 10
    );
    let netem = Netem(&lab);

    // What the peer sends is delayed, so the delay is the round trip.
    for (label, spec) in [
        ("no added delay", "off"),
        ("20 ms round trip", "delay 20ms"),
        ("100 ms round trip", "delay 100ms"),
        ("100 ms round trip, 1% loss", "delay 100ms loss 1%"),
    ] {
        if std::env::var("MESH_BENCH_NETEM").is_ok_and(|only| !label.contains(&only))
            || !wanted("tunnel")
        {
            continue;
        }
        netem.set("off");
        let direct = target.node(&lab.hostname("bench-direct"), true).await;
        let derp = target.node(&lab.hostname("bench-derp"), false).await;
        netem.set(spec);
        rate_head(&format!("Through the tunnel, {label}"));
        for (node, path) in [(&direct, "direct"), (&derp, "DERP")] {
            for (direction, name) in [(Direction::Down, "download"), (Direction::Up, "upload")] {
                for streams in [1, 8] {
                    let row = format!("{path} {name}, {streams} stream(s)");
                    if std::env::var("MESH_BENCH_ROWS").is_ok_and(|only| !row.contains(&only)) {
                        continue;
                    }
                    transfer(node, &target, direction, streams).await.row(&row);
                }
            }
        }
    }

    netem.set("delay 20ms");
    if wanted("proxy") {
        let dir = tempfile::tempdir().unwrap();
        let session = session(&target, dir.path(), &lab.hostname("bench-proxy")).await;
        settle(session.node(), &target, true).await;
        println!("\n## Through the proxy, 20 ms round trip");
        proxy_rows(&target, &session).await;
    }
    if wanted("startup") {
        startup_rows(&target, &lab.hostname("bench-start")).await;
    }
}
