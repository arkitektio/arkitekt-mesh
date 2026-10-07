//! One DERP connection (to one region), kept up with reconnects.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::net::{self, Tls};
use crate::control::types::DerpRegion;
use crate::derp::{self, DerpError, Event};
use crate::keys::PrivateKey;

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
/// ready-made frames (e.g. [`derp::send_packet`]).
pub async fn run(
    region: DerpRegion,
    node_key: PrivateKey,
    home: bool,
    events: mpsc::Sender<Received>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    sending: Sending,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        let ended = session(&region, &node_key, home, &events, &mut outgoing, &sending).await;
        sending.up.store(false, Ordering::Relaxed);
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
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Derp(#[from] DerpError),
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
        let connect = tokio::time::timeout(Duration::from_secs(10), async {
            let mut io = net::connect_named(&host, node.derp_port(), tls, &name).await?;
            let authority = if node.derp_port() == 443 {
                node.host_name.clone()
            } else {
                format!("{}:{}", node.host_name, node.derp_port())
            };
            io.write_all(derp::upgrade_request(&authority).as_bytes())
                .await?;
            let head = net::read_head(&mut io).await?;
            if head.status != 101 {
                return Err(SessionError::Other(format!(
                    "upgrade to DERP failed with HTTP {}",
                    head.status
                )));
            }
            Ok::<_, SessionError>((io, head.rest))
        });
        let (mut io, mut buf) = match connect.await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                last_err = e;
                continue;
            }
            Err(_) => {
                last_err = SessionError::Other(format!("connecting to {host} timed out"));
                continue;
            }
        };

        // Handshake: server key, our info, the server's info.
        let (kind, payload) = read_frame(&mut io, &mut buf).await?;
        let server = derp::parse_server_key(kind, &payload)?;
        io.write_all(&derp::client_info(node_key, &server)).await?;
        let (kind, payload) = read_frame(&mut io, &mut buf).await?;
        derp::check_server_info(node_key, &server, kind, &payload)?;
        if home {
            io.write_all(&derp::note_preferred(true)).await?;
        }
        tracing::debug!("connected to DERP region {} via {host}", region.region_id);
        sending.up.store(true, Ordering::Relaxed);

        let (mut rd, mut wr) = tokio::io::split(io);
        let (pong_tx, mut pong_rx) = mpsc::channel::<Vec<u8>>(8);
        let reader = async {
            loop {
                // The server sends a keepalive every minute.
                let (kind, payload) =
                    tokio::time::timeout(super::node::QUIET_LIMIT, read_frame(&mut rd, &mut buf))
                        .await
                        .map_err(|_| {
                            SessionError::Other("the DERP connection went quiet".into())
                        })??;
                match derp::parse_event(kind, payload)? {
                    Event::Ping(data) => {
                        let _ = pong_tx.try_send(derp::pong(&data));
                    }
                    Event::Restarting => {
                        return Err(SessionError::Other("server restarting".into()))
                    }
                    Event::Other => {}
                    event => {
                        if events
                            .send(Received {
                                region: region.region_id,
                                event,
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
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

async fn read_frame(
    io: &mut (impl tokio::io::AsyncRead + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(u8, Vec<u8>), SessionError> {
    loop {
        if let Some(frame) = derp::take_frame(buf)? {
            return Ok(frame);
        }
        // Read straight into the frame buffer (no stack buffer: small
        // devices have small task stacks).
        buf.reserve(4096);
        let n = io.read_buf(buf).await?;
        if n == 0 {
            return Err(SessionError::Other(
                "the DERP server closed the connection".into(),
            ));
        }
    }
}
