//! `arkitekt-meshd`: a mesh node in its own process, for apps that run it as
//! a sidecar. See the README for the protocol it speaks with its parent.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use mesh::driver::{ControlState, Refusal, Session, SessionError, SessionOptions, TurnInfo};
use serde::Serialize;
use tokio::io::AsyncReadExt;

/// One line of the stdout protocol.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Ready {
        proxy: String,
        hostname: String,
        ips: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        turn: Option<TurnInfo>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        forwards: BTreeMap<String, SocketAddr>,
        /// The peer relay's port and where peers are told to reach it.
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_relay: Option<PeerRelayInfo>,
    },
    Error {
        code: &'static str,
        message: String,
    },
    /// After `ready`, whenever the node's standing with control changes.
    Control {
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct PeerRelayInfo {
    port: u16,
    addresses: Vec<SocketAddr>,
}

fn control_event(state: ControlState) -> Event {
    let (state, reason) = match state {
        ControlState::Connected => ("connected", None),
        ControlState::Reconnecting(why) => ("reconnecting", Some(why)),
        ControlState::Refused(refusal) => {
            let why = refusal.to_string();
            let state = match refusal {
                Refusal::KeyExpired => "key_expired",
                Refusal::NeedsLogin(_) => "needs_login",
                Refusal::Refused(_) => "refused",
            };
            (state, Some(why))
        }
    };
    Event::Control { state, reason }
}

fn emit(event: &Event) {
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, event);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

struct Failure {
    code: &'static str,
    message: String,
}

fn fail(code: &'static str, message: impl ToString) -> Failure {
    Failure {
        code,
        message: message.to_string(),
    }
}

impl From<SessionError> for Failure {
    fn from(e: SessionError) -> Self {
        fail(e.code(), e)
    }
}

#[derive(Debug, Default)]
struct Args {
    statedir: Option<PathBuf>,
    hostname: Option<String>,
    control_url: Option<String>,
    listen: Option<String>,
    timeout: Option<Duration>,
    /// Bytes of TCP buffer per connection, each way.
    tcp_buffer: Option<usize>,
    ephemeral: bool,
    /// The proxy asks every request for credentials (in its url).
    proxy_auth: bool,
    turn: bool,
    /// Relay UDP for peers on this port (0: any), and where they are told
    /// to reach it.
    peer_relay_port: Option<u16>,
    peer_relay_endpoints: Vec<SocketAddr>,
    forwards: Vec<(String, String, u16)>,
    no_stdin: bool,
    version: bool,
}

/// `--flag value` and `--flag=value`, as Go's flag package takes them.
fn parse_args(raw: impl IntoIterator<Item = String>) -> Result<Args, Failure> {
    let mut args = Args::default();
    let mut raw = raw.into_iter();
    while let Some(arg) = raw.next() {
        let Some(flag) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            return Err(fail("usage", format!("unexpected argument {arg:?}")));
        };
        let (name, inline) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (flag, None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| raw.next())
                .ok_or_else(|| fail("usage", format!("--{name} needs a value")))
        };
        match name {
            "statedir" => args.statedir = Some(value()?.into()),
            "hostname" => args.hostname = Some(value()?),
            "control-url" => args.control_url = Some(value()?).filter(|u| !u.is_empty()),
            "listen" => args.listen = Some(value()?),
            "timeout" => args.timeout = Some(parse_duration(&value()?)?),
            "tcp-buffer" => {
                let raw = value()?;
                let bytes = raw
                    .parse()
                    .map_err(|_| fail("usage", format!("--tcp-buffer takes bytes, not {raw:?}")))?;
                args.tcp_buffer = Some(bytes);
            }
            "forward" => {
                let spec = value()?;
                let parsed = spec.split_once('=').and_then(|(name, target)| {
                    let (host, port) = target.rsplit_once(':')?;
                    Some((name.to_owned(), host.to_owned(), port.parse().ok()?))
                });
                args.forwards.push(parsed.ok_or_else(|| {
                    fail(
                        "usage",
                        format!("--forward takes NAME=host:port, not {spec:?}"),
                    )
                })?);
            }
            "peer-relay-port" => {
                let raw = value()?;
                args.peer_relay_port = Some(raw.parse().map_err(|_| {
                    fail(
                        "usage",
                        format!("--peer-relay-port takes a UDP port, not {raw:?}"),
                    )
                })?);
            }
            "peer-relay-endpoint" => {
                let raw = value()?;
                args.peer_relay_endpoints.push(raw.parse().map_err(|_| {
                    fail(
                        "usage",
                        format!("--peer-relay-endpoint takes ip:port, not {raw:?}"),
                    )
                })?);
            }
            "ephemeral" => args.ephemeral = true,
            "proxy-auth" => args.proxy_auth = true,
            "turn" => args.turn = true,
            "no-stdin" => args.no_stdin = true,
            "version" => args.version = true,
            _ => return Err(fail("usage", format!("unknown flag --{name}"))),
        }
    }
    Ok(args)
}

/// `90s`, `2m`, `500ms` or plain seconds.
fn parse_duration(raw: &str) -> Result<Duration, Failure> {
    let bad = || fail("usage", format!("bad duration {raw:?}"));
    let (number, unit) = raw
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| raw.split_at(i))
        .unwrap_or((raw, "s"));
    let n: u64 = number.parse().map_err(|_| bad())?;
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        "h" => Ok(Duration::from_secs(n * 3600)),
        _ => Err(bad()),
    }
}

async fn run(args: Args) -> Result<(), Failure> {
    let statedir = args
        .statedir
        .ok_or_else(|| fail("usage", "--statedir and --hostname are required"))?;
    let hostname = args
        .hostname
        .ok_or_else(|| fail("usage", "--statedir and --hostname are required"))?;

    let mut options = SessionOptions::new(statedir, hostname.clone());
    options.control_url = args.control_url;
    options.auth_key = std::env::var("ARKITEKT_MESH_AUTHKEY")
        .ok()
        .filter(|k| !k.is_empty());
    options.ephemeral = args.ephemeral;
    if let Some(timeout) = args.timeout {
        options.timeout = timeout;
    }
    if let Some(bytes) = args.tcp_buffer {
        options.limits.tcp_buffer = bytes;
    }
    let mut session = Session::start(options).await?;

    let listen = args.listen.as_deref().unwrap_or("127.0.0.1:0");
    let loopback = listen
        .parse::<SocketAddr>()
        .is_ok_and(|addr| addr.ip().is_loopback());
    if !loopback && !args.proxy_auth {
        tracing::warn!(
            "the proxy on {listen} is open to whoever reaches it, as this node: \
             pass --proxy-auth"
        );
    }
    let proxy = session
        .serve_proxy_with(listen, args.proxy_auth)
        .await
        .map_err(|e| fail("listen", format!("the proxy could not listen: {e}")))?;
    let turn = if args.turn {
        Some(session.turn().await.map_err(|e| fail("turn", e))?)
    } else {
        None
    };
    let peer_relay = match args.peer_relay_port {
        Some(port) => {
            let relay = session
                .serve_peer_relay(port, args.peer_relay_endpoints)
                .await
                .map_err(|e| fail("peer_relay", e))?;
            Some(PeerRelayInfo {
                port: relay.port(),
                addresses: relay.addrs(),
            })
        }
        None => None,
    };
    let mut forwards = BTreeMap::new();
    for (name, host, port) in args.forwards {
        let addr = session
            .forward(&host, port)
            .await
            .map_err(|e| fail("forward", format!("{name} ({host}:{port}): {e}")))?;
        forwards.insert(name, addr);
    }

    // Not the url: with --proxy-auth it carries the credentials.
    tracing::info!("connected to the mesh as {hostname}; the proxy is up");
    emit(&Event::Ready {
        proxy,
        hostname,
        ips: session
            .node()
            .addresses()
            .iter()
            .map(ToString::to_string)
            .collect(),
        turn,
        forwards,
        peer_relay,
    });
    // Serve until stopped (the session stops when dropped), saying how
    // the node stands with control whenever that changes.
    let mut control = session.node().watch_control();
    control.mark_unchanged();
    while control.changed().await.is_ok() {
        let state = control.borrow_and_update().clone();
        emit(&control_event(state));
    }
    std::future::pending::<()>().await;
    Ok(())
}

/// Resolves when the process should stop: a signal, or stdin closing (the
/// parent holds the write end, so this fires however the parent ends).
async fn stopped(watch_stdin: bool) {
    let stdin = async {
        if watch_stdin {
            let mut sink = [0u8; 1024];
            let mut stdin = tokio::io::stdin();
            while matches!(stdin.read(&mut sink).await, Ok(n) if n > 0) {}
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = stdin => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            emit(&Event::Error {
                code: e.code,
                message: e.message,
            });
            return ExitCode::FAILURE;
        }
    };
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ARKITEKT_MESHD_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    let watch_stdin = !args.no_stdin;
    let outcome = runtime.block_on(async {
        tokio::select! {
            result = run(args) => Some(result),
            // Stopping is not a failure, even mid-start.
            _ = stopped(watch_stdin) => None,
        }
    });
    // Do not wait for tasks the node leaves behind.
    runtime.shutdown_timeout(Duration::from_secs(2));
    match outcome {
        Some(Err(e)) => {
            emit(&Event::Error {
                code: e.code,
                message: e.message,
            });
            ExitCode::FAILURE
        }
        _ => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Result<Args, Failure> {
        parse_args(raw.iter().map(|s| s.to_string()))
    }

    #[test]
    fn flags_take_both_forms() {
        let a = args(&[
            "--statedir=/s",
            "--hostname",
            "h",
            "-timeout=2m",
            "--tcp-buffer=4194304",
            "--turn",
            "--forward",
            "lk=livekit:7880",
        ])
        .ok()
        .unwrap();
        assert_eq!(a.statedir, Some("/s".into()));
        assert_eq!(a.hostname.as_deref(), Some("h"));
        assert_eq!(a.timeout, Some(Duration::from_secs(120)));
        assert_eq!(a.tcp_buffer, Some(4 << 20));
        assert!(a.turn);
        assert_eq!(a.forwards, vec![("lk".into(), "livekit".into(), 7880)]);
    }

    #[test]
    fn bad_flags_are_usage_errors() {
        for bad in [
            &["--nope"][..],
            &["--forward", "livekit:7880"],
            &["--timeout", "soon"],
            &["--statedir"],
            &["positional"],
        ] {
            assert_eq!(args(bad).err().map(|e| e.code), Some("usage"), "{bad:?}");
        }
    }

    #[test]
    fn events_serialize_as_the_protocol_says() {
        let ready = Event::Ready {
            proxy: "http://127.0.0.1:1".into(),
            hostname: "h".into(),
            ips: vec!["100.64.0.1".into()],
            turn: None,
            forwards: BTreeMap::new(),
            peer_relay: None,
        };
        assert_eq!(
            serde_json::to_string(&ready).unwrap(),
            r#"{"event":"ready","proxy":"http://127.0.0.1:1","hostname":"h","ips":["100.64.0.1"]}"#
        );
        let error = Event::Error {
            code: "needs_login",
            message: "m".into(),
        };
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"event":"error","code":"needs_login","message":"m"}"#
        );
    }
}
