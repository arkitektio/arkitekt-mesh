//! Heap use of a node, measured with a counting allocator: at start, at
//! rest and during a transfer, for tailnets of different sizes; and what one
//! TLS connection costs. Numbers are printed; budgets are asserted loosely.
//!
//! `cargo test -p arkitekt-mesh --release --test memory -- --nocapture`

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

use mesh::driver::{Config, Limits, Node};
use mesh::keys::NodeIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new) };
        if !q.is_null() {
            if new > layout.size() {
                let now = CURRENT.fetch_add(new - layout.size(), Relaxed) + new - layout.size();
                PEAK.fetch_max(now, Relaxed);
            } else {
                CURRENT.fetch_sub(layout.size() - new, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Heap in use now, and the peak since the last reset, above `base`.
struct Phase(usize);

impl Phase {
    fn start() -> Self {
        let now = CURRENT.load(Relaxed);
        PEAK.store(now, Relaxed);
        Self(now)
    }
    fn current(&self) -> usize {
        CURRENT.load(Relaxed).saturating_sub(self.0)
    }
    fn peak(&self) -> usize {
        PEAK.load(Relaxed).saturating_sub(self.0)
    }
}

fn kib(bytes: usize) -> String {
    format!("{:>7.1} KiB", bytes as f64 / 1024.0)
}

async fn echo(node: &Node, host: &str, size: usize) {
    let stream = node.dial(host, 7).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        let chunk = vec![7u8; 16 * 1024];
        let mut left = size;
        while left > 0 {
            let n = left.min(chunk.len());
            wr.write_all(&chunk[..n]).await.unwrap();
            left -= n;
        }
        wr
    });
    let mut buf = vec![0u8; 16 * 1024];
    let mut got = 0;
    while got < size {
        got += rd.read(&mut buf).await.unwrap();
    }
    let _ = writer.await;
}

struct Row {
    peers: usize,
    start_peak: usize,
    idle: usize,
    transfer_peak: usize,
}

async fn measure(fake_peers: usize, limits: Limits) -> Option<Row> {
    let h = common::start_opts(false, fake_peers).await?;
    let config = Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: format!("mem-{fake_peers}"),
        ephemeral: true,
        tags: vec![],
        direct: true,
        limits,
    };

    let phase = Phase::start();
    let node = Node::start(config).await.unwrap();
    let peers = node.netmap().peers().len();
    // Let DERP, STUN and the endpoint update settle.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let start_peak = phase.peak();
    let idle = phase.current();

    let transfer = Phase::start();
    echo(&node, &h.ready.peer_name, 1 << 20).await;
    let transfer_peak = transfer.peak();
    drop(node);
    Some(Row {
        peers,
        start_peak,
        idle,
        transfer_peak,
    })
}

/// One DERP connection: TCP, TLS (rustls) and the DERP handshake.
async fn tls_connection_cost() -> Option<(usize, usize)> {
    let h = common::start().await?;
    let config = Config {
        control_url: h.ready.control_url.clone(),
        identity: NodeIdentity::generate(),
        auth_key: Some(h.ready.auth_key.clone()),
        hostname: "mem-tls".into(),
        ephemeral: true,
        tags: vec![],
        direct: false,
        limits: Limits::default(),
    };
    let node = Node::start(config).await.unwrap();
    let region = node.netmap().derp_regions.values().next().cloned().unwrap();
    let derp = region.nodes[0].clone();

    // Warm up once (tokio and rustls set up on first use), then average.
    let connect = || async {
        let mut io = mesh::driver::net::connect_named(
            &derp.derp_dial_host(),
            derp.derp_port(),
            mesh::driver::net::Tls::NoVerify,
            &derp.host_name,
        )
        .await
        .unwrap();
        let host = format!("{}:{}", derp.host_name, derp.derp_port());
        io.write_all(mesh::derp::upgrade_request(&host).as_bytes())
            .await
            .unwrap();
        let head = mesh::driver::net::read_head(&mut io).await.unwrap();
        assert_eq!(head.status, 101);
        io
    };
    drop(connect().await);
    const N: usize = 4;
    let phase = Phase::start();
    let mut held = Vec::new();
    for _ in 0..N {
        held.push(connect().await);
    }
    let (peak, held_bytes) = (phase.peak() / N, phase.current() / N);
    drop(held);
    let held = held_bytes;
    drop(node);
    Some((peak, held))
}

#[tokio::test]
async fn heap_use() {
    for (label, limits) in [
        ("default limits", Limits::default()),
        ("Limits::small()", Limits::small()),
    ] {
        let mut rows = Vec::new();
        for fake in [0, 100, 500, 1000] {
            match measure(fake, limits).await {
                Some(row) => rows.push(row),
                None => return,
            }
        }
        // Budgets, so regressions fail: well under 1 KiB per idle peer, and
        // a small transfer (with this test's own 48 KiB of buffers).
        let (one, many) = (&rows[0], &rows[rows.len() - 1]);
        let per_peer = (many.idle - one.idle) / (many.peers - one.peers);
        assert!(per_peer < 700, "{label}: {per_peer} bytes per idle peer");
        if limits == Limits::small() {
            assert!(
                one.transfer_peak < 128 << 10,
                "{label}: transfer peak {}",
                one.transfer_peak
            );
            assert!(one.idle < 192 << 10, "{label}: idle {}", one.idle);
        }
        eprintln!("\n  {label} ({per_peer} B per idle peer)\n  peers | start peak  | idle        | 1 MiB echo peak");
        for r in &rows {
            eprintln!(
                "  {:>5} | {} | {} | {}",
                r.peers,
                kib(r.start_peak),
                kib(r.idle),
                kib(r.transfer_peak)
            );
        }
    }
    if let Some((peak, held)) = tls_connection_cost().await {
        eprintln!(
            "  one TLS (DERP) connection: {} peak, {} held",
            kib(peak),
            kib(held)
        );
    }
    eprintln!();
}
