//! One DERP connection (to one region), kept up with reconnects.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::net::{self, Tls};
use crate::control::types::DerpRegion;
use crate::derp::conn::{Backoff, ConnError, DerpConn};
use crate::derp::Event;
use crate::keys::PrivateKey;
use mesh_core::time as clock;

/// What a DERP connection reports to the node.
#[derive(Debug)]
pub struct Received {
    pub region: i32,
    pub event: Event,
}

/// How a connection sends.
#[derive(Debug, Clone)]
pub struct Sending {
    /// Frames (of some size) written back to back before a pause of
    /// [`PACE`] (0: no pauses). The server queues only a few dozen packets per receiver
    /// and drops the rest of a burst.
    pub burst: usize,
    /// Set while the connection is up (frames wait in the queue otherwise).
    pub up: Arc<AtomicBool>,
}

/// The pause after a burst of frames.
const PACE: Duration = Duration::from_millis(1);
/// The size from which a frame counts towards a burst.
const PACED_FRAME: usize = 256;

/// Run a connection to `region` until `outgoing` closes. `outgoing` carries
/// ready-made frames (e.g. [`crate::derp::send_packet`]).
pub async fn run(
    region: DerpRegion,
    node_key: PrivateKey,
    home: bool,
    events: mpsc::Sender<Received>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    sending: Sending,
) {
    let mut backoff = Backoff::default();
    loop {
        let ended = session(&region, &node_key, home, &events, &mut outgoing, &sending).await;
        // A connection that came up starts the delays over.
        if sending.up.swap(false, Ordering::Relaxed) {
            backoff.reset();
        }
        match ended {
            Ok(()) => return, // the node dropped us
            Err(e) => {
                tracing::debug!(
                    "DERP region {} ({}): {e}",
                    region.region_id,
                    region.region_code
                );
            }
        }
        // The node is gone, or replaced this connection (the region moved).
        if events.is_closed() || outgoing.is_closed() {
            return;
        }
        tokio::time::sleep(backoff.next_delay()).await;
    }
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Conn(#[from] ConnError),
    #[error("{0}")]
    Other(String),
}

async fn session(
    region: &DerpRegion,
    node_key: &PrivateKey,
    home: bool,
    events: &mpsc::Sender<Received>,
    outgoing: &mut mpsc::Receiver<Vec<u8>>,
    sending: &Sending,
) -> Result<(), SessionError> {
    let mut last_err = SessionError::Other("the region has no DERP nodes".into());
    for node in region.nodes.iter().filter(|n| !n.stun_only) {
        // Dialed by IP, certified for the hostname.
        let host = node.derp_dial_host();
        let (tls, name) = match node.derp_cert_name() {
            Some(name) if !node.insecure_for_tests => (Tls::Verify, name),
            _ => (Tls::NoVerify, node.host_name.clone()),
        };
        let authority = if node.derp_port() == 443 {
            node.host_name.clone()
        } else {
            format!("{}:{}", node.host_name, node.derp_port())
        };
        let mut conn = DerpConn::new(&authority, node_key.clone(), home, clock::now());
        // Connect, upgrade and shake hands.
        let connect = tokio::time::timeout(Duration::from_secs(10), async {
            let mut io = net::connect_named(&host, node.derp_port(), tls, &name).await?;
            let mut buf = vec![0u8; 4096];
            while !conn.is_up() {
                if let Some(out) = conn.poll_transmit() {
                    io.write_all(&out).await?;
                }
                let n = io.read(&mut buf).await?;
                if n == 0 {
                    return Err(SessionError::Other(
                        "the DERP server closed the connection".into(),
                    ));
                }
                conn.handle_input(clock::now(), &buf[..n])?;
            }
            if let Some(out) = conn.poll_transmit() {
                io.write_all(&out).await?;
            }
            Ok::<_, SessionError>(io)
        });
        let io = match connect.await {
            Ok(Ok(io)) => io,
            Ok(Err(e)) => {
                last_err = e;
                continue;
            }
            Err(_) => {
                last_err = SessionError::Other(format!("connecting to {host} timed out"));
                continue;
            }
        };
        tracing::debug!("connected to DERP region {} via {host}", region.region_id);
        sending.up.store(true, Ordering::Relaxed);

        let (mut rd, mut wr) = tokio::io::split(io);
        let (pong_tx, mut pong_rx) = mpsc::channel::<Vec<u8>>(8);
        let reader = async {
            // On the heap (small devices have small task stacks), a TLS
            // record at a time: smaller reads cost relayed throughput.
            let mut buf = vec![0u8; 16 << 10];
            loop {
                let quiet = clock::to_std(conn.poll_timeout());
                let n = match tokio::time::timeout_at(quiet.into(), rd.read(&mut buf)).await {
                    Ok(n) => n?,
                    Err(_) => {
                        conn.handle_timeout(clock::now())?;
                        continue;
                    }
                };
                if n == 0 {
                    return Err(SessionError::Other(
                        "the DERP server closed the connection".into(),
                    ));
                }
                conn.handle_input(clock::now(), &buf[..n])?;
                // Pongs: written beside the packets.
                if let Some(out) = conn.poll_transmit() {
                    let _ = pong_tx.try_send(out);
                }
                while let Some(event) = conn.poll_event() {
                    if matches!(event, Event::Other) {
                        continue;
                    }
                    let received = Received {
                        region: region.region_id,
                        event,
                    };
                    if events.send(received).await.is_err() {
                        return Ok(());
                    }
                }
            }
        };
        let writer = async {
            // Frames written since `since`, to pause after a fast burst.
            let (mut written, mut since) = (0, Instant::now());
            loop {
                tokio::select! {
                    frame = outgoing.recv() => match frame {
                        Some(frame) => {
                            wr.write_all(&frame).await?;
                            // Acknowledgements and the like are not what
                            // fills a relay's queue: they are not held up.
                            if frame.len() < PACED_FRAME {
                                continue;
                            }
                            written += 1;
                            if written == sending.burst {
                                let rest = PACE.saturating_sub(since.elapsed());
                                if !rest.is_zero() {
                                    tokio::time::sleep(rest).await;
                                }
                            }
                            if written >= sending.burst || since.elapsed() >= PACE {
                                (written, since) = (0, Instant::now());
                            }
                        }
                        None => return Ok(()),
                    },
                    Some(pong) = pong_rx.recv() => wr.write_all(&pong).await?,
                }
            }
        };
        return tokio::select! {
            r = reader => r,
            r = writer => r,
        };
    }
    Err(last_err)
}
