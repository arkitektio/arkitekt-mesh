//! Frame-level cases a real server will not produce on request; the
//! conversation with one (`h2`) is in `tests/http2.rs`.

use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[kind, flags]);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut p = Vec::new();
    for (id, v) in pairs {
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&v.to_be_bytes());
    }
    frame(SETTINGS, 0, 0, &p)
}

/// The frames in `bytes` (after the preface, if it is there).
fn frames(mut bytes: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
    if bytes.starts_with(PREFACE) {
        bytes = &bytes[PREFACE.len()..];
    }
    let mut out = Vec::new();
    while bytes.len() >= 9 {
        let len = usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
        let stream = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
        out.push((bytes[3], bytes[4], stream, bytes[9..9 + len].to_vec()));
        bytes = &bytes[9 + len..];
    }
    out
}

fn status(code: &str) -> Vec<u8> {
    let mut block = Vec::new();
    hpack::encode(&[(":status", code)], &mut block);
    block
}

/// A connection past the server's SETTINGS, its output so far dropped.
fn connected(config: Config) -> Connection {
    let mut c = Connection::new(config);
    c.handle_input(&settings(&[])).unwrap();
    c.poll_transmit();
    c
}

fn events(c: &mut Connection) -> Vec<Event> {
    core::iter::from_fn(|| c.poll_event()).collect()
}

#[test]
fn opens_with_the_preface_settings_and_a_wider_window() {
    let mut c = Connection::new(Config {
        connection_window: 1 << 20,
        ..Config::default()
    });
    let out = c.poll_transmit().unwrap();
    assert!(out.starts_with(PREFACE));
    let f = frames(&out);
    assert_eq!(f[0].0, SETTINGS);
    assert_eq!((f[1].0, f[1].2), (WINDOW_UPDATE, 0));
    assert_eq!(
        u32::from_be_bytes(f[1].3[..4].try_into().unwrap()),
        (1 << 20) - 65_535
    );
}

#[test]
fn the_first_frame_must_be_settings_and_is_acked() {
    let mut c = Connection::new(Config::default());
    c.poll_transmit();
    let ping = frame(PING, 0, 0, &[0; 8]);
    assert!(matches!(
        c.handle_input(&ping),
        Err(H2Error::Connection {
            code: code::PROTOCOL_ERROR,
            ..
        })
    ));
    // A GOAWAY went out, and nothing more is taken.
    let f = frames(&c.poll_transmit().unwrap());
    assert_eq!(f.last().unwrap().0, GOAWAY);
    assert_eq!(c.handle_input(&settings(&[])), Err(H2Error::GoingAway));

    let mut c = Connection::new(Config::default());
    c.poll_transmit();
    c.handle_input(&settings(&[])).unwrap();
    let f = frames(&c.poll_transmit().unwrap());
    assert_eq!((f[0].0, f[0].1), (SETTINGS, ACK));
}

#[test]
fn frames_arrive_in_any_slicing() {
    let mut c = connected(Config::default());
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    let mut input = frame(HEADERS, END_HEADERS, id, &status("200"));
    input.extend(frame(DATA, 0, id, b"hello "));
    input.extend(frame(DATA, END_STREAM, id, b"world"));
    for b in input.chunks(1) {
        c.handle_input(b).unwrap();
    }
    assert_eq!(
        events(&mut c),
        [
            Event::Response {
                stream: id,
                status: 200,
                headers: vec![]
            },
            Event::Data {
                stream: id,
                data: b"hello ".to_vec()
            },
            Event::Data {
                stream: id,
                data: b"world".to_vec()
            },
            Event::End { stream: id },
        ]
    );
    assert_eq!(c.open_streams(), 0);
}

#[test]
fn padding_priority_informational_and_continuation() {
    let mut c = connected(Config::default());
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    // 100 Continue first, then a padded, prioritized HEADERS split over
    // two CONTINUATIONs.
    c.handle_input(&frame(HEADERS, END_HEADERS, id, &status("100")))
        .unwrap();
    let mut block = Vec::new();
    hpack::encode(
        &[(":status", "200"), ("x-a", "1"), ("x-b", "2")],
        &mut block,
    );
    let mut first = vec![3u8, 0, 0, 0, 0, 16];
    first.extend_from_slice(&block[..2]);
    first.extend_from_slice(&[0; 3]);
    c.handle_input(&frame(HEADERS, PADDED | PRIORITY_FLAG, id, &first))
        .unwrap();
    c.handle_input(&frame(CONTINUATION, 0, id, &block[2..5]))
        .unwrap();
    c.handle_input(&frame(CONTINUATION, END_HEADERS, id, &block[5..]))
        .unwrap();
    let mut data = vec![4u8];
    data.extend_from_slice(b"body");
    data.extend_from_slice(&[0; 4]);
    c.handle_input(&frame(DATA, PADDED | END_STREAM, id, &data))
        .unwrap();
    assert_eq!(
        events(&mut c),
        [
            Event::Response {
                stream: id,
                status: 200,
                headers: vec![
                    (b"x-a".to_vec(), b"1".to_vec()),
                    (b"x-b".to_vec(), b"2".to_vec())
                ],
            },
            Event::Data {
                stream: id,
                data: b"body".to_vec()
            },
            Event::End { stream: id },
        ]
    );
}

#[test]
fn a_frame_between_header_fragments_is_an_error() {
    let mut c = connected(Config::default());
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.handle_input(&frame(HEADERS, 0, id, &status("200")))
        .unwrap();
    assert!(matches!(
        c.handle_input(&frame(PING, 0, 0, &[0; 8])),
        Err(H2Error::Connection {
            code: code::PROTOCOL_ERROR,
            ..
        })
    ));
}

#[test]
fn oversized_frames_push_and_bad_hpack_end_the_connection() {
    let mut c = connected(Config::default());
    let big = frame(DATA, 0, 1, &vec![0; MIN_FRAME_SIZE + 1]);
    assert!(matches!(
        c.handle_input(&big[..9]),
        Err(H2Error::Connection {
            code: code::FRAME_SIZE_ERROR,
            ..
        })
    ));
    let mut c = connected(Config::default());
    assert!(matches!(
        c.handle_input(&frame(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2])),
        Err(H2Error::Connection {
            code: code::PROTOCOL_ERROR,
            ..
        })
    ));
    let mut c = connected(Config::default());
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    assert!(matches!(
        c.handle_input(&frame(HEADERS, END_HEADERS, id, &[0x80])),
        Err(H2Error::Connection {
            code: code::COMPRESSION_ERROR,
            ..
        })
    ));
    let f = frames(&c.poll_transmit().unwrap());
    let goaway = f.iter().find(|f| f.0 == GOAWAY).unwrap();
    assert_eq!(
        u32::from_be_bytes(goaway.3[4..8].try_into().unwrap()),
        code::COMPRESSION_ERROR
    );
}

#[test]
fn the_receive_windows_hold_and_are_handed_back() {
    let mut c = connected(Config {
        stream_window: 100,
        connection_window: 65_535,
        ..Config::default()
    });
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.poll_transmit();
    c.handle_input(&frame(HEADERS, END_HEADERS, id, &status("200")))
        .unwrap();
    c.handle_input(&frame(DATA, 0, id, &[1; 60])).unwrap();
    // Under half of the window consumed: no update yet; then one.
    c.release(id, 40);
    assert_eq!(c.poll_transmit(), None);
    c.release(id, 20);
    let f = frames(&c.poll_transmit().unwrap());
    assert_eq!(f, [(WINDOW_UPDATE, 0, id, 60u32.to_be_bytes().to_vec())]);
    // 100 more fit (40 left + 60 handed back); 101 do not: the stream is
    // reset, the connection lives.
    c.handle_input(&frame(DATA, 0, id, &[1; 100])).unwrap();
    c.handle_input(&frame(DATA, 0, id, &[1; 1])).unwrap();
    assert!(events(&mut c).contains(&Event::Reset {
        stream: id,
        code: code::FLOW_CONTROL_ERROR
    }));
    assert!(c.is_open());
}

#[test]
fn the_connection_window_is_a_connection_error() {
    let mut c = connected(Config {
        stream_window: 65_535,
        connection_window: 65_535,
        ..Config::default()
    });
    let a = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/a",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    let b = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/b",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    for id in [a, b] {
        c.handle_input(&frame(HEADERS, END_HEADERS, id, &status("200")))
            .unwrap();
    }
    for _ in 0..3 {
        c.handle_input(&frame(DATA, 0, a, &[0; 16_000])).unwrap();
    }
    c.handle_input(&frame(DATA, 0, b, &[0; 16_000])).unwrap();
    assert!(matches!(
        c.handle_input(&frame(DATA, 0, b, &[0; 2_000])),
        Err(H2Error::Connection {
            code: code::FLOW_CONTROL_ERROR,
            ..
        })
    ));
}

#[test]
fn request_bodies_wait_for_the_servers_windows() {
    let mut c = Connection::new(Config::default());
    // The server's stream window: 10 bytes.
    c.handle_input(&settings(&[(SETTINGS_INITIAL_WINDOW_SIZE, 10)]))
        .unwrap();
    c.poll_transmit();
    let id = c
        .send_request(
            &Request {
                method: "POST",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[7; 25],
            true,
        )
        .unwrap();
    let sent = |c: &mut Connection| -> (usize, bool) {
        let f = frames(&c.poll_transmit().unwrap_or_default());
        let data: Vec<_> = f.iter().filter(|f| f.0 == DATA).collect();
        (
            data.iter().map(|f| f.3.len()).sum(),
            data.iter().any(|f| f.1 & END_STREAM != 0),
        )
    };
    assert_eq!(sent(&mut c), (10, false));
    c.handle_input(&frame(WINDOW_UPDATE, 0, id, &10u32.to_be_bytes()))
        .unwrap();
    assert_eq!(sent(&mut c), (10, false));
    // A larger initial window opens the rest.
    c.handle_input(&settings(&[(SETTINGS_INITIAL_WINDOW_SIZE, 1000)]))
        .unwrap();
    assert_eq!(sent(&mut c), (5, true));
}

#[test]
fn ping_is_answered_and_goaway_refuses_later_streams() {
    let mut c = connected(Config::default());
    c.handle_input(&frame(PING, 0, 0, b"12345678")).unwrap();
    assert_eq!(
        frames(&c.poll_transmit().unwrap()),
        [(PING, ACK, 0, b"12345678".to_vec())]
    );
    // An ack is not answered.
    c.handle_input(&frame(PING, ACK, 0, b"12345678")).unwrap();
    assert_eq!(c.poll_transmit(), None);

    let a = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/a",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    let b = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/b",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    let mut goaway = a.to_be_bytes().to_vec();
    goaway.extend_from_slice(&code::NO_ERROR.to_be_bytes());
    goaway.extend_from_slice(b"bye");
    c.handle_input(&frame(GOAWAY, 0, 0, &goaway)).unwrap();
    assert_eq!(
        events(&mut c),
        [
            Event::GoAway {
                last_stream: a,
                code: code::NO_ERROR,
                debug: b"bye".to_vec()
            },
            Event::Reset {
                stream: b,
                code: code::REFUSED_STREAM
            },
        ]
    );
    // `a` still completes; nothing new opens.
    c.handle_input(&frame(HEADERS, END_HEADERS | END_STREAM, a, &status("204")))
        .unwrap();
    assert_eq!(events(&mut c).last(), Some(&Event::End { stream: a }));
    assert_eq!(
        c.send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/c",
                headers: &[]
            },
            &[],
            true
        ),
        Err(H2Error::GoingAway)
    );
}

#[test]
fn rst_stream_and_streams_the_server_did_not_get() {
    let mut c = connected(Config::default());
    let id = c
        .send_request(
            &Request {
                method: "GET",
                scheme: "https",
                authority: "x",
                path: "/",
                headers: &[],
            },
            &[],
            true,
        )
        .unwrap();
    c.handle_input(&frame(RST_STREAM, 0, id, &code::CANCEL.to_be_bytes()))
        .unwrap();
    assert_eq!(
        events(&mut c),
        [Event::Reset {
            stream: id,
            code: code::CANCEL
        }]
    );
    // Late frames for it are ignored (its window handed back).
    c.handle_input(&frame(DATA, 0, id, &[0; 10])).unwrap();
    assert!(events(&mut c).is_empty());
    // A stream we never opened is an error.
    assert!(c.handle_input(&frame(DATA, 0, 99, &[0; 1])).is_err());
}
