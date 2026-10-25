//! Our HTTP/2 client (`mesh_core::http2`) against the `h2` crate's server,
//! over an in-memory pipe. The client's input arrives in 1000-byte slices,
//! as Noise records cut a byte stream, so frames straddle them.

use std::time::Duration;

use bytes::Bytes;
use mesh_core::http2::{Config, Connection, Event, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SLICE: usize = 1000;

/// The client end: our connection, and the pipe it talks over.
struct Client {
    conn: Connection,
    io: DuplexStream,
    events: Vec<Event>,
    /// Release body bytes as they arrive (the app consuming them).
    release: bool,
}

impl Client {
    fn new(io: DuplexStream, config: Config) -> Self {
        Self {
            conn: Connection::new(config),
            io,
            events: Vec::new(),
            release: true,
        }
    }

    /// Move bytes both ways until `done` holds for the events so far.
    async fn until(&mut self, done: impl Fn(&[Event]) -> bool) {
        let mut buf = vec![0u8; SLICE];
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(out) = self.conn.poll_transmit() {
                    self.io.write_all(&out).await.unwrap();
                }
                while let Some(e) = self.conn.poll_event() {
                    if let Event::Data { stream, data } = &e {
                        if self.release {
                            self.conn.release(*stream, data.len());
                        }
                    }
                    self.events.push(e);
                }
                if done(&self.events) {
                    // What the last events produced (window updates) goes out.
                    if let Some(out) = self.conn.poll_transmit() {
                        self.io.write_all(&out).await.unwrap();
                    }
                    return;
                }
                let n = self.io.read(&mut buf).await.unwrap();
                assert!(n > 0, "the server closed the connection");
                self.conn.handle_input(&buf[..n]).unwrap();
            }
        })
        .await
        .expect("timed out");
    }

    fn body(&self, stream: u32) -> Vec<u8> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Data { stream: s, data } if *s == stream => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn response(&self, stream: u32) -> (u16, Vec<(String, String)>) {
        self.events
            .iter()
            .find_map(|e| match e {
                Event::Response {
                    stream: s,
                    status,
                    headers,
                } if *s == stream => Some((
                    *status,
                    headers
                        .iter()
                        .map(|(n, v)| {
                            (
                                String::from_utf8(n.clone()).unwrap(),
                                String::from_utf8(v.clone()).unwrap(),
                            )
                        })
                        .collect(),
                )),
                _ => None,
            })
            .expect("no response")
    }
}

fn ended(stream: u32) -> impl Fn(&[Event]) -> bool {
    move |events| {
        events
            .iter()
            .any(|e| matches!(e, Event::End { stream: s } | Event::Reset { stream: s, .. } if *s == stream))
    }
}

/// Send `data` as the stream's window allows.
async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let n = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .expect("capacity")
            .expect("capacity");
        let chunk = data.split_to(n.min(data.len()));
        send.send_data(chunk, false).unwrap();
    }
    send.send_data(Bytes::new(), true).unwrap();
}

/// What the server answers, by path.
async fn handle(
    mut request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let path = request.uri().path().to_string();
    let mut body = Vec::new();
    let recv = request.body_mut();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.unwrap();
        let _ = recv.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    let mut response = http::Response::builder().status(200);
    match path.as_str() {
        p if p.starts_with("/headers/") => {
            // Repeated and varied values: h2 indexes them in the dynamic
            // table and Huffman-codes what is shorter so.
            let n: usize = p["/headers/".len()..].parse().unwrap();
            response = response
                .header("content-type", "application/json")
                .header("x-request", n.to_string())
                .header("x-repeated", "the same value on every response")
                .header("x-binaryish", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            send.send_data(Bytes::from(format!("response {n}")), true)
                .unwrap();
        }
        "/echo" => {
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            send_all(&mut send, Bytes::from(body)).await;
        }
        "/big" => {
            let data: Vec<u8> = (0..1usize << 20).map(|i| (i % 251) as u8).collect();
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            send_all(&mut send, Bytes::from(data)).await;
        }
        "/huge-header" => {
            // Over one frame: HEADERS plus CONTINUATIONs.
            response = response.header("x-huge", "h".repeat(40_000));
            respond
                .send_response(response.body(()).unwrap(), true)
                .unwrap();
        }
        "/reset" => {
            let _send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            respond.send_reset(h2::Reason::CANCEL);
        }
        _ => {
            let response = http::Response::builder().status(404).body(()).unwrap();
            respond.send_response(response, true).unwrap();
        }
    }
}

/// A server on the other end of a pipe, handling requests until the
/// connection ends.
fn serve(io: DuplexStream, window: u32) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .initial_window_size(window)
            .initial_connection_window_size(window)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        while let Some(request) = conn.accept().await {
            let Ok((request, respond)) = request else {
                return;
            };
            tokio::spawn(handle(request, respond));
        }
    })
}

fn pair(window: u32) -> (Client, tokio::task::JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(64 << 10);
    (
        Client::new(client, Config::default()),
        serve(server, window),
    )
}

#[tokio::test]
async fn requests_share_the_dynamic_table_and_huffman() {
    let (mut c, _server) = pair(65_535);
    for n in 0..20 {
        let path = format!("/headers/{n}");
        let id = c
            .conn
            .send_request(
                &Request {
                    method: "GET",
                    scheme: "https",
                    authority: "control.test",
                    path: &path,
                    headers: &[("ts-lb", "nodekey:00")],
                },
                &[],
                true,
            )
            .unwrap();
        c.until(ended(id)).await;
        let (status, headers) = c.response(id);
        assert_eq!(status, 200);
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("x-request"), Some(n.to_string().as_str()));
        assert_eq!(get("x-repeated"), Some("the same value on every response"));
        assert_eq!(
            get("x-binaryish"),
            Some("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
        );
        assert_eq!(get("content-type"), Some("application/json"));
        assert_eq!(c.body(id), format!("response {n}").as_bytes());
    }
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/nope",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    assert_eq!(c.response(id).0, 404);
}

#[tokio::test]
async fn a_long_response_flows_as_the_window_is_handed_back() {
    let (mut c, _server) = pair(65_535);
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/big",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    let body = c.body(id);
    assert_eq!(body.len(), 1 << 20);
    assert!(body.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
}

#[tokio::test]
async fn without_releasing_the_server_stops_at_the_window() {
    let (mut c, _server) = pair(65_535);
    c.release = false;
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/big",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    // The 64 KiB windows fill and no more comes.
    c.until(|events| {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Data { data, .. } => Some(data.len()),
                _ => None,
            })
            .sum::<usize>()
            >= 64 << 10
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut buf = vec![0u8; SLICE];
    let more = tokio::time::timeout(Duration::from_millis(200), c.io.read(&mut buf)).await;
    assert!(more.is_err(), "the server sent past the window");
    assert_eq!(c.body(id).len(), 64 << 10);
}

#[tokio::test]
async fn a_large_request_body_waits_for_the_servers_window() {
    // The server's windows are 16 KiB: a 300 KB body needs many updates.
    let (mut c, _server) = pair(16 << 10);
    let body: Vec<u8> = (0..300_000usize).map(|i| (i % 253) as u8).collect();
    let id = c
        .conn
        .send_request(
            &Request {
                method: "POST",
                scheme: "https",
                authority: "control.test",
                path: "/echo",
                headers: &[("content-type", "application/json")],
            },
            &body,
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    assert_eq!(c.body(id), body);
}

#[tokio::test]
async fn a_header_block_over_frames_arrives_in_continuations() {
    let (mut c, _server) = pair(65_535);
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/huge-header",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    let (_, headers) = c.response(id);
    assert_eq!(
        headers.iter().find(|(n, _)| n == "x-huge").unwrap().1.len(),
        40_000
    );
}

#[tokio::test]
async fn a_reset_stream_leaves_the_connection_working() {
    let (mut c, _server) = pair(65_535);
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/reset",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    assert!(c
        .events
        .iter()
        .any(|e| matches!(e, Event::Reset { stream, code: 0x8 } if *stream == id)));
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/headers/1",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(ended(id)).await;
    assert_eq!(c.body(id), b"response 1");
}

#[tokio::test]
async fn pings_are_answered_and_goaway_lets_the_open_stream_finish() {
    let (client, server) = tokio::io::duplex(64 << 10);
    let mut c = Client::new(client, Config::default());
    let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
    let (pong_tx, pong_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut conn = h2::server::handshake(server).await.unwrap();
        let mut ping = conn.ping_pong().unwrap();
        let (request, mut respond) = conn.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/slow");
        // A ping, then goodbye while the stream is open.
        let pinging = tokio::spawn(async move {
            ping.ping(h2::Ping::opaque()).await.unwrap();
            let _ = pong_tx.send(());
        });
        conn.graceful_shutdown();
        let _ = opened_tx.send(());
        let respond_later = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(b"finished"), true)
                .unwrap();
        });
        // Drive the connection until it closes.
        while let Some(r) = conn.accept().await {
            assert!(r.is_err(), "a stream after GOAWAY");
        }
        let _ = (pinging.await, respond_later.await);
    });
    let id = c
        .conn
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "control.test",
                path: "/slow",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.until(|events| events.iter().any(|e| matches!(e, Event::GoAway { .. })))
        .await;
    opened_rx.await.unwrap();
    c.until(ended(id)).await;
    assert_eq!(c.body(id), b"finished");
    // The server's ping was acked.
    tokio::time::timeout(Duration::from_secs(5), pong_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!c.conn.is_open());
}
